package rebootcontrol

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type AdmissionGate struct{db *sql.DB;bootID string;now func()time.Time}
type AdmissionBlocker struct{Source string `json:"source"`;ID string `json:"id"`;State string `json:"state"`}
type AdmissionSnapshot struct{Epoch uint64;Blockers []AdmissionBlocker;Digest string}

func NewAdmissionGate(ctx context.Context,db *sql.DB,bootID string,now func()time.Time)(*AdmissionGate,error){
	if ctx==nil||db==nil||!identifierPattern.MatchString(bootID){return nil,ErrInvalid};if now==nil{now=time.Now}
	gate:=&AdmissionGate{db:db,bootID:bootID,now:now}
	tx,err:=db.BeginTx(ctx,nil);if err!=nil{return nil,err};defer tx.Rollback()
	for _,statement:=range []string{
		executionSchema,
		executionRecoverySchema,
		`CREATE TABLE IF NOT EXISTS reboot_admission_gate(singleton INTEGER PRIMARY KEY CHECK(singleton=1),epoch INTEGER NOT NULL,closed INTEGER NOT NULL,plan_id TEXT NOT NULL,fence INTEGER NOT NULL,boot_id TEXT NOT NULL)`,
		`INSERT OR IGNORE INTO reboot_admission_gate VALUES(1,0,0,'',0,'')`,
		`CREATE TABLE IF NOT EXISTS reboot_api_invocations(id TEXT PRIMARY KEY,operation TEXT NOT NULL,request_id TEXT NOT NULL,idempotency_digest TEXT NOT NULL,boot_id TEXT NOT NULL,epoch INTEGER NOT NULL,status TEXT NOT NULL,admitted_at TEXT NOT NULL,completed_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS reboot_admission_checkpoints(plan_id TEXT NOT NULL,fence INTEGER NOT NULL,epoch INTEGER NOT NULL,source TEXT NOT NULL,effect_id TEXT NOT NULL,observed_state TEXT NOT NULL,evidence_digest TEXT NOT NULL,resolved_state TEXT NOT NULL DEFAULT '',resolution_digest TEXT NOT NULL DEFAULT '',PRIMARY KEY(plan_id,fence,source,effect_id))`,
		`CREATE TABLE IF NOT EXISTS reboot_admission_schemas(plan_id TEXT NOT NULL,fence INTEGER NOT NULL,source TEXT NOT NULL,schema_digest TEXT NOT NULL,PRIMARY KEY(plan_id,fence,source))`,
		`CREATE TABLE IF NOT EXISTS reboot_admission_manifests(plan_id TEXT NOT NULL,fence INTEGER NOT NULL,epoch INTEGER NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(plan_id,fence))`,
		// Replace the old blanket host-receipt trigger so observations remain usable.
		`DROP TRIGGER IF EXISTS reboot_quiesce_operations`,
	}{if _,err=tx.ExecContext(ctx,statement);err!=nil{return nil,err}}
	for _,source:=range admissionSources{
		var definition string
		if err=tx.QueryRowContext(ctx,`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`,source.table).Scan(&definition);errors.Is(err,sql.ErrNoRows){continue}else if err!=nil{return nil,err}
		closed:=admissionClosedSQL+" AND "+source.mutation("NEW.")
		insert:=`CREATE TRIGGER IF NOT EXISTS reboot_gate_`+source.table+`_insert BEFORE INSERT ON `+source.table+` WHEN `+closed+` AND `+source.nonterminal("NEW.")+` BEGIN SELECT RAISE(ABORT,'node reboot admission closed'); END`
		// Let running effects persist terminal/ambiguous receipts, but reject a
		// new nonterminal phase or a same-state worker lease/retry after closure.
		settled:=source.terminal+",'ambiguous','uncertain','recovery_required','paused_retryable','fail_forward_required'"
		update:=`CREATE TRIGGER IF NOT EXISTS reboot_gate_`+source.table+`_update BEFORE UPDATE ON `+source.table+` WHEN `+closed+` AND COALESCE(`+source.stateSQL("NEW.")+`,'unknown') NOT IN (`+settled+`) BEGIN SELECT RAISE(ABORT,'node reboot worker admission closed'); END`
		for _,statement:=range []string{insert,update}{if _,err=tx.ExecContext(ctx,statement);err!=nil{return nil,fmt.Errorf("install reboot gate for %s: %w",source.table,err)}}
	}
	// A dead process cannot still own an invocation. Preserve it as ambiguous;
	// there may have been an effect before the domain repository was linked.
	if _,err=tx.ExecContext(ctx,`UPDATE reboot_api_invocations SET status='ambiguous' WHERE boot_id<>? AND status='active'`,bootID);err!=nil{return nil,err}
	if _,err=tx.ExecContext(ctx,`UPDATE reboot_execution_effects SET status='ambiguous' WHERE boot_id<>? AND status='active'`,bootID);err!=nil{return nil,err}
	if err=tx.Commit();err!=nil{return nil,err};return gate,nil
}

// AdmitMutation serializes admission with drain using one SQLite write. The
// durable row exists before invoking domain code, including before any effect ID.
func(gate *AdmissionGate)AdmitMutation(ctx context.Context,operation,requestID,idempotencyDigest string)(func(bool)error,error){
	if gate==nil||ctx==nil||operation==""||len(operation)>256||requestID==""||len(requestID)>256||!validDigest(idempotencyDigest){return nil,ErrInvalid}
	if mutationGateExempt(operation){return func(bool)error{return nil},nil}
	var attempt [16]byte;if _,err:=rand.Read(attempt[:]);err!=nil{return nil,err}
	id:=digestStrings(operation,requestID,idempotencyDigest,digestBytes(attempt[:]))
	result,err:=gate.db.ExecContext(ctx,`INSERT INTO reboot_api_invocations(id,operation,request_id,idempotency_digest,boot_id,epoch,status,admitted_at,completed_at) SELECT ?,?,?,?,?,epoch,'active',?,'' FROM reboot_admission_gate WHERE singleton=1 AND NOT `+admissionClosedSQL,id,operation,requestID,idempotencyDigest,gate.bootID,gate.now().UTC().Format(time.RFC3339Nano))
	if err!=nil{return nil,err};count,err:=result.RowsAffected();if err!=nil||count!=1{return nil,ErrConflict}
	return func(complete bool)error{
		finishCtx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
		state:="ambiguous";if complete{state="completed"}
		result,err:=gate.db.ExecContext(finishCtx,`UPDATE reboot_api_invocations SET status=?,completed_at=? WHERE id=? AND boot_id=? AND status='active'`,state,gate.now().UTC().Format(time.RFC3339Nano),id,gate.bootID)
		if err!=nil{return err};count,err:=result.RowsAffected();if err!=nil||count!=1{return ErrIntegrity};return nil
	},nil
}

// Close establishes one durable epoch/CAS before the first drain snapshot.
func(gate *AdmissionGate)Close(ctx context.Context,plan string,fence uint64)(uint64,error){
	if gate==nil||!identifierPattern.MatchString(plan)||fence==0||fence>maxGeneration{return 0,ErrInvalid}
	tx,err:=gate.db.BeginTx(ctx,nil);if err!=nil{return 0,err};defer tx.Rollback()
	if _,err=tx.ExecContext(ctx,`UPDATE reboot_admission_gate SET epoch=epoch+1,closed=1,plan_id=?,fence=?,boot_id=? WHERE singleton=1 AND closed=0 AND epoch<?`,plan,fence,gate.bootID,maxGeneration);err!=nil{return 0,err}
	var epoch,storedFence uint64;var closed int;var storedPlan string
	if err=tx.QueryRowContext(ctx,`SELECT epoch,closed,plan_id,fence FROM reboot_admission_gate WHERE singleton=1`).Scan(&epoch,&closed,&storedPlan,&storedFence);err!=nil{return 0,err}
	if closed!=1||storedPlan!=plan||storedFence!=fence{return 0,ErrConflict}
	if err=tx.Commit();err!=nil{return 0,err};return epoch,nil
}

func(gate *AdmissionGate)Snapshot(ctx context.Context,plan string,fence uint64,limit uint32)(AdmissionSnapshot,error){
	if gate==nil||limit==0||limit>10000{return AdmissionSnapshot{},ErrInvalid}
	tx,err:=gate.db.BeginTx(ctx,nil);if err!=nil{return AdmissionSnapshot{},err};defer tx.Rollback()
	// Acquire the writer epoch before scanning so terminal receipts cannot race
	// a deferred SQLite read-to-write transaction upgrade.
	if _,err=tx.ExecContext(ctx,`UPDATE reboot_admission_gate SET epoch=epoch WHERE singleton=1 AND closed=1 AND plan_id=? AND fence=?`,plan,fence);err!=nil{return AdmissionSnapshot{},err}
	var epoch,storedFence uint64;var closed int;var storedPlan string
	if err=tx.QueryRowContext(ctx,`SELECT epoch,closed,plan_id,fence FROM reboot_admission_gate WHERE singleton=1`).Scan(&epoch,&closed,&storedPlan,&storedFence);err!=nil{return AdmissionSnapshot{},err}
	if closed!=1||storedPlan!=plan||storedFence!=fence{return AdmissionSnapshot{},ErrConflict}
	snapshot:=AdmissionSnapshot{Epoch:epoch}
	var schemas []string
	for _,source:=range admissionSources{
		var definition string
		err=tx.QueryRowContext(ctx,`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`,source.table).Scan(&definition)
		if err!=nil&&!errors.Is(err,sql.ErrNoRows){return AdmissionSnapshot{},err}
		schema:=digestStrings(source.table,definition)
		schemas=append(schemas,source.table+":"+schema)
		if _,err=tx.ExecContext(ctx,`INSERT OR IGNORE INTO reboot_admission_schemas(plan_id,fence,source,schema_digest) VALUES(?,?,?,?)`,plan,fence,source.table,schema);err!=nil{return AdmissionSnapshot{},err}
		var storedSchema string
		if err=tx.QueryRowContext(ctx,`SELECT schema_digest FROM reboot_admission_schemas WHERE plan_id=? AND fence=? AND source=?`,plan,fence,source.table).Scan(&storedSchema);err!=nil{return AdmissionSnapshot{},err}
		if storedSchema!=schema{return AdmissionSnapshot{},ErrIntegrity};if definition==""{continue}
		// Missing triggers mean an independently-created repository escaped Init.
		var triggers int
		if err=tx.QueryRowContext(ctx,`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN (?,?)`,"reboot_gate_"+source.table+"_insert","reboot_gate_"+source.table+"_update").Scan(&triggers);err!=nil||triggers!=2{return AdmissionSnapshot{},ErrIntegrity}
		rows,err:=tx.QueryContext(ctx,`SELECT `+source.idSQL("")+`,COALESCE(`+source.stateSQL("")+`,'unknown') FROM `+source.table+` WHERE `+source.mutation("")+` AND `+source.nonterminal("")+` ORDER BY `+source.idSQL("")+` LIMIT ?`,int(limit)+1)
		if err!=nil{return AdmissionSnapshot{},err}
		for rows.Next(){var blocker AdmissionBlocker;blocker.Source=source.table;if err=rows.Scan(&blocker.ID,&blocker.State);err!=nil{rows.Close();return AdmissionSnapshot{},err};if len(blocker.ID)>4096||len(blocker.State)>256||len(snapshot.Blockers)>=int(limit){rows.Close();return AdmissionSnapshot{},ErrUnproven};snapshot.Blockers=append(snapshot.Blockers,blocker)}
		err=rows.Err();rows.Close();if err!=nil{return AdmissionSnapshot{},err}
	}
	for _,blocker:=range snapshot.Blockers{
		evidence:=digestStrings(blocker.Source,blocker.ID,blocker.State)
		if _,err=tx.ExecContext(ctx,`INSERT OR IGNORE INTO reboot_admission_checkpoints(plan_id,fence,epoch,source,effect_id,observed_state,evidence_digest) VALUES(?,?,?,?,?,?,?)`,plan,fence,epoch,blocker.Source,blocker.ID,blocker.State,evidence);err!=nil{return AdmissionSnapshot{},err}
	}
	// Bind the entire historical checkpoint set, not just the last empty poll.
	rows,err:=tx.QueryContext(ctx,`SELECT source,effect_id,observed_state,evidence_digest FROM reboot_admission_checkpoints WHERE plan_id=? AND fence=? ORDER BY source,effect_id`,plan,fence);if err!=nil{return AdmissionSnapshot{},err}
	var history []AdmissionBlocker
	for rows.Next(){var blocker AdmissionBlocker;var evidence string;if err=rows.Scan(&blocker.Source,&blocker.ID,&blocker.State,&evidence);err!=nil{rows.Close();return AdmissionSnapshot{},err};if evidence!=digestStrings(blocker.Source,blocker.ID,blocker.State)||len(history)>=10000{rows.Close();return AdmissionSnapshot{},ErrIntegrity};history=append(history,blocker)}
	err=rows.Err();rows.Close();if err!=nil{return AdmissionSnapshot{},err}
	raw,err:=json.Marshal(struct{Epoch uint64;Plan string;Fence uint64;Schemas []string;History []AdmissionBlocker}{epoch,plan,fence,schemas,history});if err!=nil{return AdmissionSnapshot{},err};snapshot.Digest=digestBytes(raw)
	if err=tx.Commit();err!=nil{return AdmissionSnapshot{},err};return snapshot,nil
}

func(gate *AdmissionGate)SealCheckpoint(ctx context.Context,plan string,fence uint64,limit uint32)(AdmissionSnapshot,error){
	snapshot,err:=gate.Snapshot(ctx,plan,fence,limit);if err!=nil{return snapshot,err};if len(snapshot.Blockers)!=0{return snapshot,nil}
	if _,err=gate.db.ExecContext(ctx,`INSERT OR IGNORE INTO reboot_admission_manifests(plan_id,fence,epoch,digest) VALUES(?,?,?,?)`,plan,fence,snapshot.Epoch,snapshot.Digest);err!=nil{return snapshot,err}
	var epoch uint64;var digest string
	if err=gate.db.QueryRowContext(ctx,`SELECT epoch,digest FROM reboot_admission_manifests WHERE plan_id=? AND fence=?`,plan,fence).Scan(&epoch,&digest);err!=nil{return snapshot,err};if epoch!=snapshot.Epoch||digest!=snapshot.Digest{return snapshot,ErrIntegrity};return snapshot,nil
}

func(gate *AdmissionGate)Wait(ctx context.Context,plan string,fence uint64,deadline time.Time,limit uint32)(AdmissionSnapshot,error){
	if deadline.IsZero(){return AdmissionSnapshot{},ErrInvalid}
	bounded,cancel:=context.WithDeadline(ctx,deadline);defer cancel()
	timer:=time.NewTicker(250*time.Millisecond);defer timer.Stop()
	for{
		snapshot,err:=gate.Snapshot(bounded,plan,fence,limit);if err!=nil{return snapshot,err}
		if len(snapshot.Blockers)==0{return snapshot,nil}
		// Ambiguous records cannot become safe through waiting alone.
		active:=false;for _,blocker:=range snapshot.Blockers{switch blocker.State{case "ambiguous","uncertain","recovery_required","paused_retryable","fail_forward_required":default:active=true}}
		if !active{return snapshot,ErrUnproven}
		select{case <-bounded.Done():return snapshot,bounded.Err();case <-timer.C:}
	}
}

// Reconcile never retries effects. It proves every exact checkpoint identity
// still exists and has a repository-defined terminal outcome before release.
func(gate *AdmissionGate)Reconcile(ctx context.Context,plan string,fence uint64)(string,error){
	snapshot,err:=gate.Snapshot(ctx,plan,fence,10000);if err!=nil{return "",err};if len(snapshot.Blockers)!=0{return "",ErrUnproven}
	var sealedEpoch uint64;var sealedDigest string
	if err=gate.db.QueryRowContext(ctx,`SELECT epoch,digest FROM reboot_admission_manifests WHERE plan_id=? AND fence=?`,plan,fence).Scan(&sealedEpoch,&sealedDigest);err!=nil{return "",err}
	if sealedEpoch!=snapshot.Epoch||sealedDigest!=snapshot.Digest{return "",ErrIntegrity}
	rows,err:=gate.db.QueryContext(ctx,`SELECT source,effect_id,observed_state,evidence_digest FROM reboot_admission_checkpoints WHERE plan_id=? AND fence=? ORDER BY source,effect_id`,plan,fence);if err!=nil{return "",err}
	type saved struct{source,id,state,evidence string};var records []saved
	for rows.Next(){var record saved;if err=rows.Scan(&record.source,&record.id,&record.state,&record.evidence);err!=nil{rows.Close();return "",err};if len(records)>=10000{rows.Close();return "",ErrUnproven};records=append(records,record)}
	err=rows.Err();rows.Close();if err!=nil{return "",err}
	proof:=[]string{snapshot.Digest}
	for _,record:=range records{
		if record.evidence!=digestStrings(record.source,record.id,record.state){return "",ErrIntegrity}
		var source *admissionSource;for i:=range admissionSources{if admissionSources[i].table==record.source{source=&admissionSources[i];break}};if source==nil{return "",ErrIntegrity}
		var state string;var unsafe int
		if err=gate.db.QueryRowContext(ctx,`SELECT COALESCE(`+source.stateSQL("")+`,'unknown'),`+source.nonterminal("")+` FROM `+source.table+` WHERE `+source.idSQL("")+`=?`,record.id).Scan(&state,&unsafe);err!=nil{return "",err};if unsafe!=0{return "",ErrUnproven}
		evidence:=digestStrings(record.evidence,state)
		if _,err=gate.db.ExecContext(ctx,`UPDATE reboot_admission_checkpoints SET resolved_state=?,resolution_digest=? WHERE plan_id=? AND fence=? AND source=? AND effect_id=?`,state,evidence,plan,fence,record.source,record.id);err!=nil{return "",err}
		proof=append(proof,evidence)
	}
	return digestStrings(proof...),nil
}

func(gate *AdmissionGate)Open(ctx context.Context)error{
	var plan,boot string;var fence uint64;var closed int
	if err:=gate.db.QueryRowContext(ctx,`SELECT plan_id,fence,closed,boot_id FROM reboot_admission_gate WHERE singleton=1`).Scan(&plan,&fence,&closed,&boot);err!=nil{return err};if closed==0{return nil}
	// A same-boot cancellation before arming can seal a drained empty set;
	// startup recovery may never manufacture a missing pre-reboot checkpoint.
	var manifests int
	if err:=gate.db.QueryRowContext(ctx,`SELECT COUNT(*) FROM reboot_admission_manifests WHERE plan_id=? AND fence=?`,plan,fence).Scan(&manifests);err!=nil{return err}
	if manifests==0{
		var phase,marker string
		if err:=gate.db.QueryRowContext(ctx,`SELECT phase,COALESCE(json_extract(state_json,'$.marker_digest'),'') FROM reboot_states WHERE plan_id=? AND fence=?`,plan,fence).Scan(&phase,&marker);err!=nil{return err}
		if boot!=gate.bootID||marker!=""||phase!="draining"&&phase!="checkpointed"{return ErrIntegrity}
		if _,err:=gate.SealCheckpoint(ctx,plan,fence,10000);err!=nil{return err}
	}
	if _,err:=gate.Reconcile(ctx,plan,fence);err!=nil{return err}
	result,err:=gate.db.ExecContext(ctx,`UPDATE reboot_admission_gate SET closed=0 WHERE singleton=1 AND closed=1 AND plan_id=? AND fence=?`,plan,fence);if err!=nil{return err};count,err:=result.RowsAffected();if err!=nil||count!=1{return ErrConflict};return nil
}
