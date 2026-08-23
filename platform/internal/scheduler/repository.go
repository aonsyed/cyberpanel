package scheduler

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

const Schema = `
CREATE TABLE IF NOT EXISTS scheduler_schedules (
 id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 enabled INTEGER NOT NULL,
 next_logical_at TIMESTAMP NOT NULL,
 priority INTEGER NOT NULL,
 overlap_policy TEXT NOT NULL,
 generation INTEGER NOT NULL,
 lease_token TEXT NOT NULL DEFAULT '',
 lease_fence INTEGER NOT NULL DEFAULT 0,
 lease_until TIMESTAMP NULL,
 schedule_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS scheduler_schedules_due ON scheduler_schedules(enabled,next_logical_at,priority,id);
CREATE TABLE IF NOT EXISTS scheduler_occurrences (
 id TEXT PRIMARY KEY,
 schedule_id TEXT NOT NULL,
 schedule_generation INTEGER NOT NULL,
 logical_at TIMESTAMP NOT NULL,
 ready_at TIMESTAMP NOT NULL,
 priority INTEGER NOT NULL,
 state TEXT NOT NULL,
 attempt INTEGER NOT NULL,
 fence_token INTEGER NOT NULL,
 lease_token TEXT NOT NULL DEFAULT '',
 lease_until TIMESTAMP NULL,
 deadline TIMESTAMP NULL,
 occurrence_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 UNIQUE(schedule_id,logical_at)
);
CREATE INDEX IF NOT EXISTS scheduler_occurrences_ready ON scheduler_occurrences(state,ready_at,priority,id);
CREATE INDEX IF NOT EXISTS scheduler_occurrences_active ON scheduler_occurrences(schedule_id,state,lease_until,id);
`

const maximumOccurrenceAttempts = uint32(32)

type Repository struct { DB *sql.DB }

type ScheduleClaim struct {
	Schedule   Schedule
	LeaseToken string
	FenceToken uint64
	LeaseUntil time.Time
}

type OccurrenceLease struct {
	Schedule  Schedule
	Occurrence Occurrence
}

func (repository Repository) Bootstrap(ctx context.Context) error {
	if repository.DB == nil || ctx == nil { return ErrInvalid }
	_, err := repository.DB.ExecContext(ctx, Schema)
	return err
}

func (repository Repository) PutSchedule(ctx context.Context, schedule Schedule, expectedGeneration uint64, now time.Time) error {
	if repository.DB == nil || ctx == nil || schedule.Validate() != nil || now.IsZero() || now.Location() != time.UTC || schedule.Generation != expectedGeneration+1 { return ErrInvalid }
	encoded, err := json.Marshal(schedule); if err != nil { return err }
	if expectedGeneration == 0 {
		_, err = repository.DB.ExecContext(ctx, `INSERT INTO scheduler_schedules(id,tenant_id,enabled,next_logical_at,priority,overlap_policy,generation,schedule_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, schedule.ID,schedule.TenantID,boolInteger(schedule.Enabled),schedule.NextLogicalTime,schedule.Priority,schedule.OverlapPolicy,schedule.Generation,encoded,now)
		if err != nil { return err }
		return nil
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE scheduler_schedules SET tenant_id=?,enabled=?,next_logical_at=?,priority=?,overlap_policy=?,generation=?,lease_token='',lease_until=NULL,schedule_json=?,updated_at=? WHERE id=? AND generation=?`, schedule.TenantID,boolInteger(schedule.Enabled),schedule.NextLogicalTime,schedule.Priority,schedule.OverlapPolicy,schedule.Generation,encoded,now,schedule.ID,expectedGeneration)
	if err != nil { return err }
	return requireOne(result)
}

func (repository Repository) Schedule(ctx context.Context, id ScheduleID) (Schedule, error) {
	if repository.DB == nil || ctx == nil || !validToken(string(id),3,128) { return Schedule{},ErrInvalid }
	var encoded []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT schedule_json FROM scheduler_schedules WHERE id=?`,id).Scan(&encoded)
	if errors.Is(err,sql.ErrNoRows) { return Schedule{},ErrNotFound }; if err != nil { return Schedule{},err }
	var schedule Schedule; if json.Unmarshal(encoded,&schedule) != nil || schedule.ID != id || schedule.Validate() != nil { return Schedule{},ErrConflict }
	return schedule,nil
}

func (repository Repository) Occurrence(ctx context.Context, id OccurrenceID) (Occurrence, error) {
	if repository.DB == nil || ctx == nil || !validToken(string(id),3,128) { return Occurrence{},ErrInvalid }
	var encoded []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT occurrence_json FROM scheduler_occurrences WHERE id=?`,id).Scan(&encoded)
	if errors.Is(err,sql.ErrNoRows) { return Occurrence{},ErrNotFound }; if err != nil { return Occurrence{},err }
	var occurrence Occurrence; if json.Unmarshal(encoded,&occurrence) != nil || occurrence.ID != id || occurrence.Validate() != nil { return Occurrence{},ErrConflict }
	return occurrence,nil
}

func (repository Repository) AdmitOccurrence(ctx context.Context, schedule Schedule, occurrence Occurrence) (Occurrence, bool, error) {
	if repository.DB == nil || ctx == nil || schedule.Validate() != nil || occurrence.Validate() != nil || occurrence.ScheduleID != schedule.ID || occurrence.ScheduleGeneration != schedule.Generation { return Occurrence{},false,ErrInvalid }
	tx, err := repository.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable}); if err != nil { return Occurrence{},false,err }; defer tx.Rollback()
	var generation uint64;if err=tx.QueryRowContext(ctx,`SELECT generation FROM scheduler_schedules WHERE id=?`,schedule.ID).Scan(&generation);errors.Is(err,sql.ErrNoRows){return Occurrence{},false,ErrNotFound}else if err!=nil{return Occurrence{},false,err}else if generation!=schedule.Generation{return Occurrence{},false,ErrStale}
	value, created, err := admitOccurrenceTx(ctx,tx,schedule,occurrence); if err != nil { return Occurrence{},false,err }
	if err=tx.Commit();err!=nil{return Occurrence{},false,err}
	return value,created,nil
}

func (repository Repository) ClaimDueSchedules(ctx context.Context, now time.Time, workerID string, leaseDuration time.Duration, limit int) ([]ScheduleClaim, error) {
	if repository.DB == nil || ctx == nil || now.IsZero() || now.Location() != time.UTC || !validToken(workerID,3,128) || leaseDuration < 5*time.Second || leaseDuration > 5*time.Minute || limit < 1 || limit > 128 { return nil,ErrInvalid }
	tx, err := repository.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable}); if err != nil { return nil,err }; defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT schedule_json,lease_fence FROM scheduler_schedules WHERE enabled=1 AND next_logical_at<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY priority DESC,next_logical_at,id LIMIT ?`,now,now,limit)
	if err != nil { return nil,err }
	type candidate struct{ schedule Schedule; fence uint64 }; candidates:=make([]candidate,0,limit)
	for rows.Next(){var encoded []byte;var fence uint64;if err=rows.Scan(&encoded,&fence);err!=nil{rows.Close();return nil,err};var schedule Schedule;if json.Unmarshal(encoded,&schedule)!=nil||schedule.Validate()!=nil{rows.Close();return nil,ErrConflict};candidates=append(candidates,candidate{schedule:schedule,fence:fence})}
	if err=rows.Close();err!=nil{return nil,err};if err=rows.Err();err!=nil{return nil,err}
	claims:=make([]ScheduleClaim,0,len(candidates));until:=now.Add(leaseDuration)
	for _,candidate:=range candidates{
		fence:=candidate.fence+1;if fence==0{return nil,ErrConflict};token:=leaseToken("schedule",workerID,string(candidate.schedule.ID),fence,now)
		result,updateErr:=tx.ExecContext(ctx,`UPDATE scheduler_schedules SET lease_token=?,lease_fence=?,lease_until=?,updated_at=? WHERE id=? AND generation=? AND lease_fence=? AND (lease_until IS NULL OR lease_until<=?)`,token,fence,until,now,candidate.schedule.ID,candidate.schedule.Generation,candidate.fence,now);if updateErr!=nil{return nil,updateErr}
		affected,rowsErr:=result.RowsAffected();if rowsErr!=nil{return nil,rowsErr};if affected==1{claims=append(claims,ScheduleClaim{Schedule:candidate.schedule,LeaseToken:token,FenceToken:fence,LeaseUntil:until})}
	}
	if err=tx.Commit();err!=nil{return nil,err};return claims,nil
}

func (repository Repository) AdvanceSchedule(ctx context.Context, claim ScheduleClaim, next time.Time, occurrences []Occurrence, now time.Time) error {
	if repository.DB == nil || ctx == nil || claim.Schedule.Validate()!=nil || !validToken(claim.LeaseToken,16,192) || claim.FenceToken==0 || claim.LeaseUntil.IsZero() || !logicalMinute(next) || !next.After(claim.Schedule.NextLogicalTime) || now.IsZero() || now.Location()!=time.UTC || now.After(claim.LeaseUntil) || len(occurrences)==0 || len(occurrences)>1024 { return ErrInvalid }
	cursor:=claim.Schedule.NextLogicalTime;for _,occurrence:=range occurrences{if !occurrence.LogicalTime.Equal(cursor){return ErrInvalid};following,nextErr:=NextLogicalTime(claim.Schedule.Expression,claim.Schedule.Timezone,cursor);if nextErr!=nil{return nextErr};cursor=following};if !cursor.Equal(next){return ErrInvalid}
	tx,err:=repository.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return err};defer tx.Rollback()
	for _,occurrence:=range occurrences{if occurrence.ScheduleID!=claim.Schedule.ID||occurrence.ScheduleGeneration!=claim.Schedule.Generation{return ErrInvalid};if _,_,err=admitOccurrenceTx(ctx,tx,claim.Schedule,occurrence);err!=nil{return err}}
	updated:=claim.Schedule;updated.NextLogicalTime=next;encoded,err:=json.Marshal(updated);if err!=nil{return err}
	result,err:=tx.ExecContext(ctx,`UPDATE scheduler_schedules SET next_logical_at=?,lease_token='',lease_until=NULL,schedule_json=?,updated_at=? WHERE id=? AND generation=? AND lease_token=? AND lease_fence=? AND lease_until>=? AND next_logical_at=?`,next,encoded,now,claim.Schedule.ID,claim.Schedule.Generation,claim.LeaseToken,claim.FenceToken,now,claim.Schedule.NextLogicalTime);if err!=nil{return err}
	if err=requireOne(result);err!=nil{return err};return tx.Commit()
}

func (repository Repository) ReleaseScheduleClaim(ctx context.Context, claim ScheduleClaim, now time.Time) error {
	if repository.DB==nil||ctx==nil||claim.Schedule.ID==""||!validToken(claim.LeaseToken,16,192)||claim.FenceToken==0||now.IsZero()||now.Location()!=time.UTC{return ErrInvalid}
	result,err:=repository.DB.ExecContext(ctx,`UPDATE scheduler_schedules SET lease_token='',lease_until=NULL,updated_at=? WHERE id=? AND generation=? AND lease_token=? AND lease_fence=?`,now,claim.Schedule.ID,claim.Schedule.Generation,claim.LeaseToken,claim.FenceToken);if err!=nil{return err};return requireOne(result)
}

func (repository Repository) ClaimOccurrences(ctx context.Context, now time.Time, workerID string, leaseGrace time.Duration, limit int) ([]OccurrenceLease,error) {
	if repository.DB==nil||ctx==nil||now.IsZero()||now.Location()!=time.UTC||!validToken(workerID,3,128)||leaseGrace<5*time.Second||leaseGrace>5*time.Minute||limit<1||limit>256{return nil,ErrInvalid}
	tx,err:=repository.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return nil,err};defer tx.Rollback()
	rows,err:=tx.QueryContext(ctx,`SELECT o.occurrence_json,s.schedule_json FROM scheduler_occurrences o JOIN scheduler_schedules s ON s.id=o.schedule_id WHERE o.ready_at<=? AND (o.state=? OR (o.state IN (?,?) AND o.lease_until<=?)) ORDER BY o.priority DESC,o.ready_at,o.id LIMIT ?`,now,OccurrenceAdmitted,OccurrenceLeased,OccurrenceRunning,now,limit*8);if err!=nil{return nil,err}
	type candidate struct{occurrence Occurrence;schedule Schedule};candidates:=make([]candidate,0,limit*2)
	for rows.Next(){var occurrenceJSON,scheduleJSON []byte;if err=rows.Scan(&occurrenceJSON,&scheduleJSON);err!=nil{rows.Close();return nil,err};var occurrence Occurrence;var schedule Schedule;if json.Unmarshal(occurrenceJSON,&occurrence)!=nil||json.Unmarshal(scheduleJSON,&schedule)!=nil||occurrence.Validate()!=nil||schedule.Validate()!=nil{rows.Close();return nil,ErrConflict};candidates=append(candidates,candidate{occurrence:occurrence,schedule:schedule})}
	if err=rows.Close();err!=nil{return nil,err};if err=rows.Err();err!=nil{return nil,err}
	leases:=make([]OccurrenceLease,0,limit)
	for _,candidate:=range candidates{
		if len(leases)>=limit{break};occurrence,schedule:=candidate.occurrence,candidate.schedule
		if !schedule.Enabled||occurrence.ScheduleGeneration!=schedule.Generation{if err=terminalizeUnclaimable(ctx,tx,occurrence,"schedule_generation_inactive",now);err!=nil{return nil,err};continue}
		if occurrence.Attempt>=maximumOccurrenceAttempts{if err=terminalizeUnclaimable(ctx,tx,occurrence,"attempt_limit_exhausted",now);err!=nil{return nil,err};continue}
		if schedule.OverlapPolicy==OverlapForbid{var active int;if err=tx.QueryRowContext(ctx,`SELECT COUNT(*) FROM scheduler_occurrences WHERE schedule_id=? AND id<>? AND state IN (?,?) AND lease_until>?`,schedule.ID,occurrence.ID,OccurrenceLeased,OccurrenceRunning,now).Scan(&active);err!=nil{return nil,err};if active>0{if occurrence.State==OccurrenceAdmitted{if err=skipOccurrenceTx(ctx,tx,occurrence,"overlap_forbidden",now);err!=nil{return nil,err}};continue}}
		fence,attempt:=occurrence.FenceToken+1,occurrence.Attempt+1;if fence==0{return nil,ErrConflict};token:=leaseToken("occurrence",workerID,string(occurrence.ID),fence,now);deadline:=now.Add(schedule.Timeout);until:=deadline.Add(leaseGrace)
		previousState,previousFence:=occurrence.State,occurrence.FenceToken;occurrence.State,occurrence.Attempt,occurrence.FenceToken=OccurrenceLeased,attempt,fence;occurrence.LeaseToken,occurrence.LeaseUntil,occurrence.Deadline,occurrence.UpdatedAt=token,until,deadline,now;occurrence.Receipt,occurrence.Failure="",""
		encoded,marshalErr:=json.Marshal(occurrence);if marshalErr!=nil{return nil,marshalErr}
		result,updateErr:=tx.ExecContext(ctx,`UPDATE scheduler_occurrences SET state=?,attempt=?,fence_token=?,lease_token=?,lease_until=?,deadline=?,occurrence_json=?,updated_at=? WHERE id=? AND state=? AND fence_token=? AND (lease_until IS NULL OR lease_until<=?)`,occurrence.State,occurrence.Attempt,occurrence.FenceToken,token,until,deadline,encoded,now,occurrence.ID,previousState,previousFence,now);if updateErr!=nil{return nil,updateErr};affected,rowsErr:=result.RowsAffected();if rowsErr!=nil{return nil,rowsErr};if affected==1{leases=append(leases,OccurrenceLease{Schedule:schedule,Occurrence:occurrence})}
	}
	if err=tx.Commit();err!=nil{return nil,err};return leases,nil
}

func (repository Repository) StartOccurrence(ctx context.Context, lease OccurrenceLease, now time.Time) (Occurrence,error) {
	occurrence:=lease.Occurrence;if repository.DB==nil||ctx==nil||lease.Schedule.Validate()!=nil||occurrence.State!=OccurrenceLeased||occurrence.Validate()!=nil||occurrence.ScheduleID!=lease.Schedule.ID||occurrence.ScheduleGeneration!=lease.Schedule.Generation||now.IsZero()||now.Location()!=time.UTC{return Occurrence{},ErrInvalid};if now.After(occurrence.LeaseUntil){return Occurrence{},ErrStale}
	previous:=occurrence;occurrence.State,occurrence.UpdatedAt=OccurrenceRunning,now;encoded,err:=json.Marshal(occurrence);if err!=nil{return Occurrence{},err}
	result,err:=repository.DB.ExecContext(ctx,`UPDATE scheduler_occurrences SET state=?,occurrence_json=?,updated_at=? WHERE id=? AND schedule_generation=? AND state=? AND fence_token=? AND lease_token=? AND lease_until>=? AND EXISTS(SELECT 1 FROM scheduler_schedules s WHERE s.id=scheduler_occurrences.schedule_id AND s.generation=? AND s.enabled=1)`,occurrence.State,encoded,now,occurrence.ID,occurrence.ScheduleGeneration,OccurrenceLeased,previous.FenceToken,previous.LeaseToken,now,lease.Schedule.Generation);if err!=nil{return Occurrence{},err};if err=requireOne(result);err!=nil{return Occurrence{},err};return occurrence,nil
}

func (repository Repository) CompleteOccurrence(ctx context.Context, occurrence Occurrence, receipt string, now time.Time) (Occurrence,error) {
	if repository.DB==nil||ctx==nil||occurrence.State!=OccurrenceRunning||occurrence.Validate()!=nil||!validReceipt(receipt)||now.IsZero()||now.Location()!=time.UTC{return Occurrence{},ErrInvalid};if now.After(occurrence.LeaseUntil){return Occurrence{},ErrStale}
	previous:=occurrence;occurrence.State,occurrence.Receipt,occurrence.LeaseToken,occurrence.LeaseUntil,occurrence.UpdatedAt=OccurrenceCompleted,receipt,"",time.Time{},now
	if err:=repository.saveOccurrenceCAS(ctx,occurrence,previous,OccurrenceRunning,now);err!=nil{return Occurrence{},err};return occurrence,nil
}

func (repository Repository) FailOccurrence(ctx context.Context, occurrence Occurrence, failure string, now time.Time) (Occurrence,error) {
	if repository.DB==nil||ctx==nil||occurrence.State!=OccurrenceRunning||occurrence.Validate()!=nil||!validFailure(failure)||now.IsZero()||now.Location()!=time.UTC{return Occurrence{},ErrInvalid};if now.After(occurrence.LeaseUntil){return Occurrence{},ErrStale}
	previous:=occurrence;occurrence.State,occurrence.Failure,occurrence.LeaseToken,occurrence.LeaseUntil,occurrence.UpdatedAt=OccurrenceFailed,failure,"",time.Time{},now
	if err:=repository.saveOccurrenceCAS(ctx,occurrence,previous,OccurrenceRunning,now);err!=nil{return Occurrence{},err};return occurrence,nil
}

func (repository Repository) saveOccurrenceCAS(ctx context.Context, occurrence, previous Occurrence, expected OccurrenceState, now time.Time) error {
	if occurrence.Validate()!=nil{return ErrInvalid};encoded,err:=json.Marshal(occurrence);if err!=nil{return err}
	result,err:=repository.DB.ExecContext(ctx,`UPDATE scheduler_occurrences SET state=?,attempt=?,fence_token=?,lease_token=?,lease_until=?,deadline=?,occurrence_json=?,updated_at=? WHERE id=? AND schedule_generation=? AND state=? AND fence_token=? AND lease_token=? AND lease_until>=?`,occurrence.State,occurrence.Attempt,occurrence.FenceToken,occurrence.LeaseToken,nullableTime(occurrence.LeaseUntil),nullableTime(occurrence.Deadline),encoded,now,occurrence.ID,occurrence.ScheduleGeneration,expected,previous.FenceToken,previous.LeaseToken,now);if err!=nil{return err};return requireOne(result)
}

func admitOccurrenceTx(ctx context.Context,tx *sql.Tx,schedule Schedule,occurrence Occurrence)(Occurrence,bool,error){
	if schedule.Validate()!=nil||occurrence.Validate()!=nil||occurrence.ScheduleID!=schedule.ID||occurrence.ScheduleGeneration!=schedule.Generation{return Occurrence{},false,ErrInvalid}
	encoded,err:=json.Marshal(occurrence);if err!=nil{return Occurrence{},false,err}
	result,err:=tx.ExecContext(ctx,`INSERT INTO scheduler_occurrences(id,schedule_id,schedule_generation,logical_at,ready_at,priority,state,attempt,fence_token,lease_token,lease_until,deadline,occurrence_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,occurrence.ID,occurrence.ScheduleID,occurrence.ScheduleGeneration,occurrence.LogicalTime,occurrence.ReadyAt,schedule.Priority,occurrence.State,occurrence.Attempt,occurrence.FenceToken,occurrence.LeaseToken,nullableTime(occurrence.LeaseUntil),nullableTime(occurrence.Deadline),encoded,occurrence.UpdatedAt);if err!=nil{return Occurrence{},false,err}
	affected,err:=result.RowsAffected();if err!=nil{return Occurrence{},false,err};if affected==1{return occurrence,true,nil}
	var storedJSON []byte;if err=tx.QueryRowContext(ctx,`SELECT occurrence_json FROM scheduler_occurrences WHERE id=? OR (schedule_id=? AND logical_at=?) LIMIT 1`,occurrence.ID,occurrence.ScheduleID,occurrence.LogicalTime).Scan(&storedJSON);err!=nil{return Occurrence{},false,err};var stored Occurrence;if json.Unmarshal(storedJSON,&stored)!=nil||stored.Validate()!=nil||stored.ID!=occurrence.ID||stored.ScheduleID!=occurrence.ScheduleID||stored.ScheduleGeneration!=occurrence.ScheduleGeneration||!stored.LogicalTime.Equal(occurrence.LogicalTime)||!stored.ReadyAt.Equal(occurrence.ReadyAt){return Occurrence{},false,ErrConflict};return stored,false,nil
}

func terminalizeUnclaimable(ctx context.Context,tx *sql.Tx,occurrence Occurrence,reason string,now time.Time)error{if occurrence.State==OccurrenceAdmitted{return skipOccurrenceTx(ctx,tx,occurrence,reason,now)};previous:=occurrence;occurrence.State,occurrence.Failure,occurrence.LeaseToken,occurrence.LeaseUntil,occurrence.UpdatedAt=OccurrenceFailed,reason,"",time.Time{},now;encoded,err:=json.Marshal(occurrence);if err!=nil{return err};result,err:=tx.ExecContext(ctx,`UPDATE scheduler_occurrences SET state=?,lease_token='',lease_until=NULL,occurrence_json=?,updated_at=? WHERE id=? AND state=? AND fence_token=? AND lease_token=?`,occurrence.State,encoded,now,occurrence.ID,previous.State,previous.FenceToken,previous.LeaseToken);if err!=nil{return err};return requireOne(result)}
func skipOccurrenceTx(ctx context.Context,tx *sql.Tx,occurrence Occurrence,reason string,now time.Time)error{if occurrence.State!=OccurrenceAdmitted||!validFailure(reason){return ErrInvalid};occurrence.State,occurrence.Failure,occurrence.UpdatedAt=OccurrenceSkipped,reason,now;encoded,err:=json.Marshal(occurrence);if err!=nil{return err};result,err:=tx.ExecContext(ctx,`UPDATE scheduler_occurrences SET state=?,occurrence_json=?,updated_at=? WHERE id=? AND state=? AND fence_token=0`,occurrence.State,encoded,now,occurrence.ID,OccurrenceAdmitted);if err!=nil{return err};return requireOne(result)}

func requireOne(result sql.Result)error{affected,err:=result.RowsAffected();if err!=nil{return err};if affected!=1{return ErrStale};return nil}
func boolInteger(value bool)int{if value{return 1};return 0}
func nullableTime(value time.Time)any{if value.IsZero(){return nil};return value}
func leaseToken(kind,worker,id string,fence uint64,now time.Time)string{sum:=sha256.Sum256([]byte("cyberpanel:scheduler:lease:v1\x00"+kind+"\x00"+worker+"\x00"+id+"\x00"+now.UTC().Format(time.RFC3339Nano)+"\x00"+strconv.FormatUint(fence,10)));return "lease-"+hex.EncodeToString(sum[:24])}
