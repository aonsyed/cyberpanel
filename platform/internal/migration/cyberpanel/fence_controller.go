package cyberpanel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

type GateLease struct { Token string; SourceGeneration uint64; ExpiresAt time.Time; EvidenceDigest string }
type GateCheck struct { Token string; MigrationID migration.ID; SiteSourceIDs []string; SourceGeneration,ExpectedFence uint64; FenceDigest string }

// TypedSiteQuiescer is implemented by the separately deployed legacy helper.
// The helper owns the source-specific mapping from a site ID to its PHP,
// database, mail, cron, and filesystem write gates.
type TypedSiteQuiescer interface {
	Freeze(context.Context,QuiesceRequest)(GateLease,error)
	Verify(context.Context,GateCheck)error
	Thaw(context.Context,GateCheck)error
	Commit(context.Context,GateCheck)error
	Rollback(context.Context,GateCheck)error
}

type SQLFenceController struct { database *sql.DB; quiescer TypedSiteQuiescer; clock func()time.Time }

func NewSQLFenceController(database *sql.DB,quiescer TypedSiteQuiescer)(*SQLFenceController,error){if database==nil||quiescer==nil{return nil,ErrInvalid};return &SQLFenceController{database:database,quiescer:quiescer,clock:time.Now},nil}

func(c *SQLFenceController)EnsureSchema(ctx context.Context)error{if c==nil||c.database==nil||ctx==nil{return ErrInvalid};_,err:=c.database.ExecContext(ctx,`CREATE TABLE IF NOT EXISTS migration_source_fences(
		handle_id VARCHAR(54) PRIMARY KEY,migration_id VARCHAR(96) NOT NULL,source_installation_id VARCHAR(255) NOT NULL,site_source_ids MEDIUMBLOB NOT NULL,
		mode VARCHAR(32) NOT NULL,expected_fence BIGINT UNSIGNED NOT NULL,target_plan_digest CHAR(64) NOT NULL,approval_digest CHAR(64) NOT NULL,
		gate_token MEDIUMTEXT NOT NULL,source_generation BIGINT UNSIGNED NOT NULL,expires_at VARCHAR(35) NOT NULL,evidence_digest CHAR(64) NOT NULL,
		fence_digest CHAR(64) NOT NULL,state VARCHAR(32) NOT NULL,created_at VARCHAR(35) NOT NULL,updated_at VARCHAR(35) NOT NULL,
		UNIQUE(migration_id,expected_fence))`);return err}

func(c *SQLFenceController)BeginQuiesce(ctx context.Context,request QuiesceRequest)(QuiesceObservation,error){if c==nil||ctx==nil||!request.MigrationID.Valid()||request.SourceInstallationID==""||request.ExpectedFence==0||!isDigest(request.TargetPlanDigest)||!isDigest(request.ApprovalDigest)||(request.Mode!="write_fence"&&request.Mode!="service_fence"){return QuiesceObservation{},ErrInvalid};sites,err:=json.Marshal(request.SiteSourceIDs);if err!=nil{return QuiesceObservation{},err};if existing,found,err:=c.existing(ctx,request.MigrationID,request.ExpectedFence);err!=nil{return QuiesceObservation{},err}else if found{if !reusableFenceRecord(existing,request,c.clock().UTC()){return QuiesceObservation{},ErrDenied};return existing.observation(),nil};lease,err:=c.quiescer.Freeze(ctx,request);if err!=nil{return QuiesceObservation{},err};if strings.TrimSpace(lease.Token)==""||lease.SourceGeneration==0||lease.ExpiresAt.IsZero()||!lease.ExpiresAt.After(c.clock().UTC())||!isDigest(lease.EvidenceDigest){c.thawLease(request,lease);return QuiesceObservation{},ErrInvalid};handleID,err:=randomHandle();if err!=nil{c.thawLease(request,lease);return QuiesceObservation{},err};now:=c.clock().UTC().Format(time.RFC3339Nano);_,err=c.database.ExecContext(ctx,`INSERT INTO migration_source_fences(handle_id,migration_id,source_installation_id,site_source_ids,mode,expected_fence,target_plan_digest,approval_digest,gate_token,source_generation,expires_at,evidence_digest,fence_digest,state,created_at,updated_at)VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,handleID,request.MigrationID.String(),request.SourceInstallationID,sites,request.Mode,request.ExpectedFence,request.TargetPlanDigest,request.ApprovalDigest,lease.Token,lease.SourceGeneration,lease.ExpiresAt.UTC().Format(time.RFC3339Nano),lease.EvidenceDigest,"","unbound",now,now);if err!=nil{c.thawLease(request,lease);if existing,found,readErr:=c.existing(ctx,request.MigrationID,request.ExpectedFence);readErr==nil&&found&&reusableFenceRecord(existing,request,c.clock().UTC()){return existing.observation(),nil};return QuiesceObservation{},errors.Join(err)};return QuiesceObservation{HandleID:handleID,SourceGeneration:lease.SourceGeneration,ExpiresAt:lease.ExpiresAt.UTC(),EvidenceDigest:lease.EvidenceDigest},nil}

func(c *SQLFenceController)BindFence(ctx context.Context,handleID string,fence migration.SourceFence)error{if c==nil||ctx==nil||!validHandle(handleID)||!fence.MigrationID.Valid()||fence.Generation==0||fence.Fence==0||!isDigest(fence.Digest){return ErrInvalid};result,err:=c.database.ExecContext(ctx,`UPDATE migration_source_fences SET fence_digest=?,state='bound',updated_at=? WHERE handle_id=? AND migration_id=? AND source_generation=? AND expected_fence=? AND state='unbound'`,fence.Digest,c.clock().UTC().Format(time.RFC3339Nano),handleID,fence.MigrationID.String(),fence.Generation,fence.Fence);if err!=nil{return err};affected,err:=result.RowsAffected();if err!=nil{return err};if affected==1{return nil};record,readErr:=c.byHandle(ctx,handleID);if readErr==nil&&record.migrationID==fence.MigrationID&&record.sourceGeneration==fence.Generation&&record.expectedFence==fence.Fence&&record.fenceDigest==fence.Digest&&record.state=="bound"{return nil};return errors.Join(readErr,ErrChanged)}

func(c *SQLFenceController)AbortUnbound(ctx context.Context,handleID string)error{if c==nil||ctx==nil||!validHandle(handleID){return ErrInvalid};record,err:=c.byHandle(ctx,handleID);if errors.Is(err,sql.ErrNoRows){return nil};if err!=nil{return err};if record.state=="aborted"{return nil};if record.state=="unbound"{result,updateErr:=c.database.ExecContext(ctx,`UPDATE migration_source_fences SET state='aborting',updated_at=? WHERE handle_id=? AND state='unbound'`,c.clock().UTC().Format(time.RFC3339Nano),handleID);if updateErr!=nil{return updateErr};affected,updateErr:=result.RowsAffected();if updateErr!=nil||affected!=1{return errors.Join(updateErr,ErrChanged)};record.state="aborting"};if record.state!="aborting"{return ErrDenied};if err:=c.quiescer.Thaw(ctx,record.check());err!=nil{return err};result,err:=c.database.ExecContext(ctx,`UPDATE migration_source_fences SET state='aborted',updated_at=? WHERE handle_id=? AND state='aborting'`,c.clock().UTC().Format(time.RFC3339Nano),handleID);if err!=nil{return err};affected,err:=result.RowsAffected();if err!=nil||affected!=1{return errors.Join(err,ErrChanged)};return nil}

func(c *SQLFenceController)AssertQuiesced(ctx context.Context,command FenceCommand)error{record,err:=c.bound(ctx,command,true);if err!=nil{return err};if record.state!="bound"{return ErrDenied};return c.quiescer.Verify(ctx,record.check())}
func(c *SQLFenceController)Unquiesce(ctx context.Context,command FenceCommand)error{return c.apply(ctx,command,"unquiesced",c.quiescer.Thaw)}
func(c *SQLFenceController)Commit(ctx context.Context,command FenceCommand)error{return c.apply(ctx,command,"committed",c.quiescer.Commit)}
func(c *SQLFenceController)Rollback(ctx context.Context,command FenceCommand)error{return c.apply(ctx,command,"rolled_back",c.quiescer.Rollback)}

type fenceRecord struct{handleID string;migrationID migration.ID;sourceInstallationID string;siteSourceIDs []string;mode string;expectedFence,sourceGeneration uint64;targetPlanDigest,approvalDigest,gateToken,evidenceDigest,fenceDigest,state string;expiresAt time.Time}
func(r fenceRecord)observation()QuiesceObservation{return QuiesceObservation{HandleID:r.handleID,SourceGeneration:r.sourceGeneration,ExpiresAt:r.expiresAt,EvidenceDigest:r.evidenceDigest}}
func(r fenceRecord)check()GateCheck{return GateCheck{Token:r.gateToken,MigrationID:r.migrationID,SiteSourceIDs:append([]string(nil),r.siteSourceIDs...),SourceGeneration:r.sourceGeneration,ExpectedFence:r.expectedFence,FenceDigest:r.fenceDigest}}
func reusableFenceRecord(record fenceRecord,request QuiesceRequest,now time.Time)bool{return record.sourceInstallationID==request.SourceInstallationID&&sameStringSequence(record.siteSourceIDs,request.SiteSourceIDs)&&record.mode==request.Mode&&record.targetPlanDigest==request.TargetPlanDigest&&record.approvalDigest==request.ApprovalDigest&&now.Before(record.expiresAt)&&(record.state=="unbound"||record.state=="bound")}
func sameStringSequence(left,right []string)bool{if len(left)!=len(right){return false};for index:=range left{if left[index]!=right[index]{return false}};return true}
func(c *SQLFenceController)thawLease(request QuiesceRequest,lease GateLease){if c==nil||c.quiescer==nil||strings.TrimSpace(lease.Token)==""{return};cleanup,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel();_ = c.quiescer.Thaw(cleanup,GateCheck{Token:lease.Token,MigrationID:request.MigrationID,SiteSourceIDs:append([]string(nil),request.SiteSourceIDs...),SourceGeneration:lease.SourceGeneration,ExpectedFence:request.ExpectedFence})}

func(c *SQLFenceController)apply(ctx context.Context,command FenceCommand,target string,operation func(context.Context,GateCheck)error)error{requireLive:=target=="committed";record,err:=c.bound(ctx,command,requireLive);if err!=nil{return err};if record.state==target{return nil};if record.state!="bound"{return ErrDenied};if err:=operation(ctx,record.check());err!=nil{return err};result,err:=c.database.ExecContext(ctx,`UPDATE migration_source_fences SET state=?,updated_at=? WHERE handle_id=? AND state='bound'`,target,c.clock().UTC().Format(time.RFC3339Nano),record.handleID);if err!=nil{return err};affected,err:=result.RowsAffected();if err!=nil||affected!=1{return errors.Join(err,ErrChanged)};return nil}
func(c *SQLFenceController)bound(ctx context.Context,command FenceCommand,requireLive bool)(fenceRecord,error){if c==nil||ctx==nil||!command.MigrationID.Valid()||command.SourceGeneration==0||command.ExpectedFence==0||!isDigest(command.FenceDigest){return fenceRecord{},ErrInvalid};record,err:=c.read(ctx,`SELECT handle_id,migration_id,source_installation_id,site_source_ids,mode,expected_fence,source_generation,target_plan_digest,approval_digest,gate_token,evidence_digest,fence_digest,state,expires_at FROM migration_source_fences WHERE fence_digest=?`,command.FenceDigest);if err!=nil{return fenceRecord{},err};if record.migrationID!=command.MigrationID||record.sourceGeneration!=command.SourceGeneration||record.expectedFence!=command.ExpectedFence{return fenceRecord{},ErrDenied};if requireLive&&!c.clock().UTC().Before(record.expiresAt)&&record.state=="bound"{return fenceRecord{},ErrDenied};return record,nil}
func(c *SQLFenceController)existing(ctx context.Context,id migration.ID,fence uint64)(fenceRecord,bool,error){record,err:=c.read(ctx,`SELECT handle_id,migration_id,source_installation_id,site_source_ids,mode,expected_fence,source_generation,target_plan_digest,approval_digest,gate_token,evidence_digest,fence_digest,state,expires_at FROM migration_source_fences WHERE migration_id=? AND expected_fence=?`,id.String(),fence);if errors.Is(err,sql.ErrNoRows){return fenceRecord{},false,nil};return record,err==nil,err}
func(c *SQLFenceController)byHandle(ctx context.Context,handleID string)(fenceRecord,error){return c.read(ctx,`SELECT handle_id,migration_id,source_installation_id,site_source_ids,mode,expected_fence,source_generation,target_plan_digest,approval_digest,gate_token,evidence_digest,fence_digest,state,expires_at FROM migration_source_fences WHERE handle_id=?`,handleID)}
func(c *SQLFenceController)read(ctx context.Context,query string,args ...any)(fenceRecord,error){var record fenceRecord;var migrationID,sites,expiresAt string;err:=c.database.QueryRowContext(ctx,query,args...).Scan(&record.handleID,&migrationID,&record.sourceInstallationID,&sites,&record.mode,&record.expectedFence,&record.sourceGeneration,&record.targetPlanDigest,&record.approvalDigest,&record.gateToken,&record.evidenceDigest,&record.fenceDigest,&record.state,&expiresAt);if err!=nil{return fenceRecord{},err};id,err:=migration.NewID(migrationID);if err!=nil{return fenceRecord{},ErrInvalid};record.migrationID=id;if err:=json.Unmarshal([]byte(sites),&record.siteSourceIDs);err!=nil{return fenceRecord{},ErrInvalid};record.expiresAt,err=time.Parse(time.RFC3339Nano,expiresAt);if err!=nil{return fenceRecord{},ErrInvalid};return record,nil}
func randomHandle()(string,error){value:=make([]byte,24);if _,err:=rand.Read(value);err!=nil{return"",err};return"fence_"+hex.EncodeToString(value),nil}
func validHandle(value string)bool{if !strings.HasPrefix(value,"fence_")||len(value)!=54{return false};_,err:=hex.DecodeString(strings.TrimPrefix(value,"fence_"));return err==nil}

var _ FenceController=(*SQLFenceController)(nil)
