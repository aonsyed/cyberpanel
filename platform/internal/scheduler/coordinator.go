package scheduler

import (
	"context"
	"errors"
	"time"
)

const (
	DefaultScheduleClaimLimit = 32
	DefaultOccurrenceLimit    = 128
	MaximumRunScheduleLimit   = 128
	MaximumRunOccurrenceLimit = 256
)

type DispatchRequest struct {
	Schedule   Schedule   `json:"schedule"`
	Occurrence Occurrence `json:"occurrence"`
}

type DispatchReceipt struct {
	OccurrenceID OccurrenceID `json:"occurrence_id"`
	FenceToken   uint64       `json:"fence_token"`
	Receipt      string       `json:"receipt"`
	CompletedAt  time.Time    `json:"completed_at"`
}

func (receipt DispatchReceipt) Validate(request DispatchRequest) error {
	if receipt.OccurrenceID != request.Occurrence.ID || receipt.FenceToken != request.Occurrence.FenceToken || !validReceipt(receipt.Receipt) || receipt.CompletedAt.IsZero() || receipt.CompletedAt.Location()!=time.UTC || receipt.CompletedAt.Before(request.Occurrence.UpdatedAt) || receipt.CompletedAt.After(request.Occurrence.Deadline) { return ErrInvalid }
	return nil
}

// Dispatcher accepts only a typed target, must return when the context ends,
// and must use Occurrence.ID as its idempotency key and FenceToken as its
// stale-attempt fence.
type Dispatcher interface {
	Dispatch(context.Context, DispatchRequest) (DispatchReceipt, error)
}

type Coordinator struct {
	Repository       Repository
	Dispatcher       Dispatcher
	WorkerID         string
	ScheduleLease    time.Duration
	OccurrenceGrace  time.Duration
	ScheduleLimit    int
	OccurrenceLimit  int
	Now              func() time.Time
}

type RunReport struct {
	SchedulesClaimed    int `json:"schedules_claimed"`
	OccurrencesAdmitted int `json:"occurrences_admitted"`
	OccurrencesSkipped  int `json:"occurrences_skipped"`
	OccurrencesClaimed  int `json:"occurrences_claimed"`
	OccurrencesCompleted int `json:"occurrences_completed"`
	OccurrencesFailed   int `json:"occurrences_failed"`
	StaleLeasesFenced   int `json:"stale_leases_fenced"`
}

func (coordinator Coordinator) RunOnce(ctx context.Context) (RunReport,error) {
	if ctx==nil||coordinator.Repository.DB==nil||coordinator.Dispatcher==nil||!validToken(coordinator.WorkerID,3,128){return RunReport{},ErrInvalid}
	scheduleLimit:=coordinator.ScheduleLimit;if scheduleLimit==0{scheduleLimit=DefaultScheduleClaimLimit};occurrenceLimit:=coordinator.OccurrenceLimit;if occurrenceLimit==0{occurrenceLimit=DefaultOccurrenceLimit}
	if scheduleLimit<1||scheduleLimit>MaximumRunScheduleLimit||occurrenceLimit<=int(MaxReplayOccurrences)||occurrenceLimit>MaximumRunOccurrenceLimit{return RunReport{},ErrInvalid}
	scheduleLease:=coordinator.ScheduleLease;if scheduleLease==0{scheduleLease=time.Minute};occurrenceGrace:=coordinator.OccurrenceGrace;if occurrenceGrace==0{occurrenceGrace=30*time.Second}
	if scheduleLease<5*time.Second||scheduleLease>5*time.Minute||occurrenceGrace<5*time.Second||occurrenceGrace>5*time.Minute{return RunReport{},ErrInvalid}
	now:=coordinator.currentTime();claims,err:=coordinator.Repository.ClaimDueSchedules(ctx,now,coordinator.WorkerID,scheduleLease,scheduleLimit);if err!=nil{return RunReport{},err}
	report:=RunReport{SchedulesClaimed:len(claims)};remaining:=occurrenceLimit
	for _,claim:=range claims{
		if err=ctx.Err();err!=nil{return report,err}
		if remaining<=int(MaxReplayOccurrences){if releaseErr:=coordinator.Repository.ReleaseScheduleClaim(ctx,claim,coordinator.currentTime());releaseErr!=nil&&!errors.Is(releaseErr,ErrStale){return report,releaseErr};continue}
		next,occurrences,planErr:=materializeDue(claim.Schedule,now,remaining)
		if planErr!=nil{_ = coordinator.Repository.ReleaseScheduleClaim(ctx,claim,coordinator.currentTime());return report,planErr}
		if advanceErr:=coordinator.Repository.AdvanceSchedule(ctx,claim,next,occurrences,coordinator.currentTime());advanceErr!=nil{return report,advanceErr}
		for _,occurrence:=range occurrences{if occurrence.State==OccurrenceSkipped{report.OccurrencesSkipped++}else{report.OccurrencesAdmitted++}}
		remaining-=len(occurrences)
	}
	leases,err:=coordinator.Repository.ClaimOccurrences(ctx,coordinator.currentTime(),coordinator.WorkerID,occurrenceGrace,occurrenceLimit);if err!=nil{return report,err};report.OccurrencesClaimed=len(leases)
	for _,lease:=range leases{
		if lease.Occurrence.Attempt>1{report.StaleLeasesFenced++}
		started,startErr:=coordinator.Repository.StartOccurrence(ctx,lease,coordinator.currentTime());if errors.Is(startErr,ErrStale){report.StaleLeasesFenced++;continue};if startErr!=nil{return report,startErr}
		request:=DispatchRequest{Schedule:lease.Schedule,Occurrence:started};dispatchContext,cancel:=context.WithDeadline(ctx,started.Deadline);receipt,dispatchErr:=coordinator.Dispatcher.Dispatch(dispatchContext,request);dispatchContextErr:=dispatchContext.Err();cancel()
		finished:=coordinator.currentTime()
		if dispatchErr!=nil{failure:="dispatch_failed";if errors.Is(dispatchErr,context.DeadlineExceeded)||errors.Is(dispatchContextErr,context.DeadlineExceeded){failure="dispatch_timeout"};if _,err=coordinator.Repository.FailOccurrence(ctx,started,failure,finished);errors.Is(err,ErrStale){report.StaleLeasesFenced++;continue}else if err!=nil{return report,err};report.OccurrencesFailed++;continue}
		if receipt.Validate(request)!=nil||receipt.CompletedAt.After(finished){if _,err=coordinator.Repository.FailOccurrence(ctx,started,"invalid_dispatch_receipt",finished);errors.Is(err,ErrStale){report.StaleLeasesFenced++;continue}else if err!=nil{return report,err};report.OccurrencesFailed++;continue}
		if _,err=coordinator.Repository.CompleteOccurrence(ctx,started,receipt.Receipt,receipt.CompletedAt);errors.Is(err,ErrStale){report.StaleLeasesFenced++;continue}else if err!=nil{return report,err};report.OccurrencesCompleted++
	}
	return report,nil
}

func (coordinator Coordinator) currentTime() time.Time { if coordinator.Now!=nil{return coordinator.Now().UTC()};return time.Now().UTC() }

func materializeDue(schedule Schedule, now time.Time, capacity int)(time.Time,[]Occurrence,error){
	if schedule.Validate()!=nil||now.IsZero()||capacity<1||capacity>MaximumRunOccurrenceLimit||schedule.NextLogicalTime.After(now){return time.Time{},nil,ErrInvalid}
	logicalTimes:=make([]time.Time,0,capacity);cursor:=schedule.NextLogicalTime
	for !cursor.After(now)&&len(logicalTimes)<capacity{logicalTimes=append(logicalTimes,cursor);next,err:=NextLogicalTime(schedule.Expression,schedule.Timezone,cursor);if err!=nil{return time.Time{},nil,err};cursor=next}
	moreDue:=!cursor.After(now)
	if moreDue{reserve:=0;if schedule.MissedRunPolicy==MissedLatest{reserve=1}else if schedule.MissedRunPolicy==MissedBoundedReplay{reserve=int(schedule.ReplayLimit)};processed:=len(logicalTimes)-reserve;if processed<1{return time.Time{},nil,ErrInvalid};cursor=logicalTimes[processed];logicalTimes=logicalTimes[:processed]}
	states:=make([]OccurrenceState,len(logicalTimes));reasons:=make([]string,len(logicalTimes));for index:=range states{states[index]=OccurrenceSkipped;reasons[index]="missed_backlog_deferred"}
	if !moreDue{
		switch schedule.MissedRunPolicy{
		case MissedSkip:
			currentMinute:=now.UTC().Truncate(time.Minute);for index,logical:=range logicalTimes{if logical.Equal(currentMinute){states[index]=OccurrenceAdmitted;reasons[index]=""}else{reasons[index]="missed_run_skipped"}}
		case MissedLatest:
			for index:=range reasons{reasons[index]="latest_only_omitted"};states[len(states)-1],reasons[len(reasons)-1]=OccurrenceAdmitted,""
		case MissedBoundedReplay:
			start:=len(states)-int(schedule.ReplayLimit);if start<0{start=0};for index:=range states{if index>=start{states[index],reasons[index]=OccurrenceAdmitted,""}else{reasons[index]="bounded_replay_omitted"}}
		default:return time.Time{},nil,ErrInvalid
		}
	}
	occurrences:=make([]Occurrence,0,len(logicalTimes));for index,logical:=range logicalTimes{occurrence,err:=NewOccurrence(schedule,logical,states[index],reasons[index]);if err!=nil{return time.Time{},nil,err};occurrences=append(occurrences,occurrence)}
	return cursor,occurrences,nil
}
