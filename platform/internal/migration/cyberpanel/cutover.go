package cyberpanel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

type QuiesceRequest struct {
	MigrationID migration.ID
	SourceInstallationID string
	SiteSourceIDs []string
	Mode string
	ExpectedFence uint64
	TargetPlanDigest string
	ApprovalDigest string
}

type QuiesceObservation struct {
	HandleID string
	SourceGeneration uint64
	ExpiresAt time.Time
	EvidenceDigest string
}

type FenceCommand struct {
	MigrationID migration.ID
	FenceDigest string
	SourceGeneration uint64
	ExpectedFence uint64
}

// FenceController is the complete privileged surface exposed by the legacy
// source helper. Implementations map these five typed operations to local
// service/read-only gates. No shell fragment, SQL text, service name, or path
// crosses the protocol boundary.
type FenceController interface {
	BeginQuiesce(context.Context, QuiesceRequest) (QuiesceObservation, error)
	BindFence(context.Context, string, migration.SourceFence) error
	AbortUnbound(context.Context, string) error
	AssertQuiesced(context.Context, FenceCommand) error
	Unquiesce(context.Context, FenceCommand) error
	Commit(context.Context, FenceCommand) error
	Rollback(context.Context, FenceCommand) error
}

type FinalDeltaBuilder interface {
	BuildFinalDelta(context.Context, migration.SourceFence, migration.Manifest) (migration.Manifest, error)
}

type Cutover struct {
	sourceKind migration.SourceKind
	plans PlanStore
	verifier PlanVerifier
	controller FenceController
	delta FinalDeltaBuilder
	clock func() time.Time
}

func NewCutover(plans PlanStore, verifier PlanVerifier, controller FenceController, delta FinalDeltaBuilder) (*Cutover, error) {
	return NewCutoverForSource(migration.SourceCyberPanel,plans,verifier,controller,delta)
}

func NewCutoverForSource(sourceKind migration.SourceKind, plans PlanStore, verifier PlanVerifier, controller FenceController, delta FinalDeltaBuilder) (*Cutover, error) {
	if plans==nil||verifier==nil||controller==nil||delta==nil{return nil,ErrInvalid}
	if sourceKind!=migration.SourceCyberPanel&&sourceKind!=migration.SourceCPanel{return nil,ErrInvalid}
	return &Cutover{sourceKind:sourceKind,plans:plans,verifier:verifier,controller:controller,delta:delta,clock:time.Now},nil
}

func (c *Cutover) Quiesce(ctx context.Context, migrationID migration.ID, targetPlan migration.Plan, expectedFence uint64) (migration.SourceFence, error) {
	if c==nil||ctx==nil||!migrationID.Valid()||expectedFence==0||targetPlan.MigrationID!=migrationID||targetPlan.DryRunDigest==""||targetPlan.ApprovedAt==nil{return migration.SourceFence{},ErrInvalid}
	approved,err:=c.plans.ApprovedPlan(ctx,migrationID);if err!=nil{return migration.SourceFence{},err};if err:=c.verifier.VerifyApprovedPlan(ctx,approved,c.clock().UTC());err!=nil{return migration.SourceFence{},err}
	if approved.Plan.TargetPlanDigest==""||approved.Plan.TargetPlanDigest!=targetPlan.DryRunDigest{return migration.SourceFence{},ErrDenied}
	approvalDigest,err:=approvedPlanDigest(approved);if err!=nil{return migration.SourceFence{},err}
	request:=QuiesceRequest{MigrationID:migrationID,SourceInstallationID:approved.Plan.SourceInstallationID,SiteSourceIDs:append([]string(nil),approved.Plan.SiteSourceIDs...),Mode:approved.Plan.QuiesceMode,ExpectedFence:expectedFence,TargetPlanDigest:targetPlan.DryRunDigest,ApprovalDigest:approvalDigest}
	observation,err:=c.controller.BeginQuiesce(ctx,request);if err!=nil{return migration.SourceFence{},err}
	if strings.TrimSpace(observation.HandleID)==""||observation.SourceGeneration==0||observation.ExpiresAt.IsZero()||!observation.ExpiresAt.After(c.clock().UTC())||!isDigest(observation.EvidenceDigest){_ = c.controller.AbortUnbound(ctx,observation.HandleID);return migration.SourceFence{},ErrInvalid}
	fence:=migration.SourceFence{MigrationID:migrationID,Generation:observation.SourceGeneration,Fence:expectedFence,ExpiresAt:observation.ExpiresAt.UTC()}
	fence.Digest=cutoverFenceDigest(fence,approved.Plan.TargetPlanDigest,approvalDigest,observation.EvidenceDigest)
	if err:=c.controller.BindFence(ctx,observation.HandleID,fence);err!=nil{_ = c.controller.AbortUnbound(ctx,observation.HandleID);return migration.SourceFence{},err}
	return fence,nil
}

func (c *Cutover) Unquiesce(ctx context.Context, fence migration.SourceFence) error {
	command,err:=c.command(ctx,fence,false);if err!=nil{return err};return c.controller.Unquiesce(ctx,command)
}

func (c *Cutover) FinalDelta(ctx context.Context, fence migration.SourceFence, base migration.Manifest) (migration.Manifest, error) {
	command,err:=c.command(ctx,fence,true);if err!=nil{return migration.Manifest{},err};if base.MigrationID!=fence.MigrationID||base.Source!=c.sourceKind{return migration.Manifest{},ErrInvalid};if err:=c.controller.AssertQuiesced(ctx,command);err!=nil{return migration.Manifest{},err};delta,err:=c.delta.BuildFinalDelta(ctx,fence,base);if err!=nil{return migration.Manifest{},err};if delta.MigrationID!=fence.MigrationID||delta.Source!=c.sourceKind||delta.SourceGeneration!=fence.Generation{return migration.Manifest{},ErrChanged};return delta,nil
}

func (c *Cutover) CommitSource(ctx context.Context, fence migration.SourceFence) error { command,err:=c.command(ctx,fence,true);if err!=nil{return err};return c.controller.Commit(ctx,command) }
func (c *Cutover) RollbackSource(ctx context.Context, fence migration.SourceFence) error { command,err:=c.command(ctx,fence,false);if err!=nil{return err};return c.controller.Rollback(ctx,command) }

func (c *Cutover) command(ctx context.Context,fence migration.SourceFence,requireLive bool)(FenceCommand,error){if c==nil||ctx==nil||!fence.MigrationID.Valid()||fence.Generation==0||fence.Fence==0||!isDigest(fence.Digest)||fence.ExpiresAt.IsZero(){return FenceCommand{},ErrInvalid};if requireLive&&!c.clock().UTC().Before(fence.ExpiresAt){return FenceCommand{},ErrDenied};return FenceCommand{MigrationID:fence.MigrationID,FenceDigest:fence.Digest,SourceGeneration:fence.Generation,ExpectedFence:fence.Fence},nil}

func (e *Extractor) BuildFinalDelta(ctx context.Context, fence migration.SourceFence, base migration.Manifest) (migration.Manifest,error){if e==nil||ctx==nil||base.MigrationID!=fence.MigrationID{return migration.Manifest{},ErrInvalid};manifest,err:=e.Discover(ctx,fence.MigrationID);if err!=nil{return migration.Manifest{},err};if manifest.SourceGeneration!=fence.Generation{return migration.Manifest{},ErrChanged};return manifest,nil}

func cutoverFenceDigest(fence migration.SourceFence,targetPlanDigest,approvalDigest,evidenceDigest string)string{raw,_:=json.Marshal(struct{Domain string `json:"domain"`;MigrationID migration.ID `json:"migration_id"`;Generation uint64 `json:"generation"`;Fence uint64 `json:"fence"`;ExpiresAt time.Time `json:"expires_at"`;TargetPlanDigest string `json:"target_plan_digest"`;ApprovalDigest string `json:"approval_digest"`;EvidenceDigest string `json:"evidence_digest"`}{Domain:"cyberpanel-source-fence-v1",MigrationID:fence.MigrationID,Generation:fence.Generation,Fence:fence.Fence,ExpiresAt:fence.ExpiresAt.UTC(),TargetPlanDigest:targetPlanDigest,ApprovalDigest:approvalDigest,EvidenceDigest:evidenceDigest});sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:])}

var _ migration.CutoverSource=(*Cutover)(nil)
var _ FinalDeltaBuilder=(*Extractor)(nil)
