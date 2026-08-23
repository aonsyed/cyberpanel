package cpanel

import (
	"crypto/ed25519"
	"database/sql"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanel"
)

type ResourceSelection = cyberpanel.ResourceSelection
type SourcePlan = cyberpanel.SourcePlan
type ApprovedPlan = cyberpanel.ApprovedPlan
type PlanStore = cyberpanel.PlanStore
type PlanVerifier = cyberpanel.PlanVerifier
type LocalApprovalPolicy = cyberpanel.LocalApprovalPolicy
type LocalApprovalVerifier = cyberpanel.LocalApprovalVerifier
type FilePlanStore = cyberpanel.FilePlanStore
type SecretSealer = cyberpanel.SecretSealer
type X25519Sealer = cyberpanel.X25519Sealer
type ArtifactID = cyberpanel.ArtifactID
type SecretRef = cyberpanel.SecretRef
type Snapshot = cyberpanel.Snapshot

func NewLocalApprovalVerifier(policy LocalApprovalPolicy)(*LocalApprovalVerifier,error){return cyberpanel.NewLocalApprovalVerifier(policy)}
func OpenFilePlanStore(rootPath string)(*FilePlanStore,error){return cyberpanel.OpenFilePlanStore(rootPath)}
func SignApprovedPlan(plan SourcePlan,approvedAt time.Time,keyID string,privateKey ed25519.PrivateKey)(ApprovedPlan,error){return cyberpanel.SignApprovedPlan(plan,approvedAt,keyID,privateKey)}
func NewX25519Sealer(keyID string,targetPublicKey []byte)(*X25519Sealer,error){return cyberpanel.NewX25519Sealer(keyID,targetPublicKey)}
func CanonicalManifestSchemaHash()string{return cyberpanel.CanonicalManifestSchemaHash()}

type ExtractorConfig struct {
	PlanStore PlanStore
	PlanVerifier PlanVerifier
	Collector cyberpanel.Collector
	Artifacts cyberpanel.ArtifactCatalog
	Secrets cyberpanel.SecretSource
	Sealer SecretSealer
	Chunks *migration.ChunkStore
	SigningKeyID string
	SigningKey ed25519.PrivateKey
	ExtractorVersion string
	Clock func()time.Time
}

type Extractor struct { *cyberpanel.Extractor }

func NewExtractor(config ExtractorConfig)(*Extractor,error){value,err:=cyberpanel.NewExtractor(cyberpanel.ExtractorConfig{SourceKind:migration.SourceCPanel,PlanStore:config.PlanStore,PlanVerifier:config.PlanVerifier,Collector:config.Collector,Artifacts:config.Artifacts,Secrets:config.Secrets,Sealer:config.Sealer,Chunks:config.Chunks,SigningKeyID:config.SigningKeyID,SigningKey:config.SigningKey,ExtractorVersion:config.ExtractorVersion,Clock:config.Clock});if err!=nil{return nil,err};return &Extractor{Extractor:value},nil}

type QuiesceRequest = cyberpanel.QuiesceRequest
type QuiesceObservation = cyberpanel.QuiesceObservation
type FenceCommand = cyberpanel.FenceCommand
type FenceController = cyberpanel.FenceController
type FinalDeltaBuilder = cyberpanel.FinalDeltaBuilder
type Cutover = cyberpanel.Cutover
type GateScope = cyberpanel.GateScope
type ComponentLease = cyberpanel.ComponentLease
type ComponentAction = cyberpanel.ComponentAction
type ComponentGate = cyberpanel.ComponentGate
type NamedComponentGate = cyberpanel.NamedComponentGate
type GenerationReader = cyberpanel.GenerationReader
type CoordinatedQuiescer = cyberpanel.CoordinatedQuiescer
type SQLFenceController = cyberpanel.SQLFenceController
type TypedSiteQuiescer = cyberpanel.TypedSiteQuiescer

func NewCutover(plans PlanStore,verifier PlanVerifier,controller FenceController,delta FinalDeltaBuilder)(*Cutover,error){return cyberpanel.NewCutoverForSource(migration.SourceCPanel,plans,verifier,controller,delta)}
func NewCoordinatedQuiescer(components []NamedComponentGate,generation GenerationReader)(*CoordinatedQuiescer,error){return cyberpanel.NewCoordinatedQuiescer(components,generation)}
func NewSQLFenceController(database *sql.DB,quiescer TypedSiteQuiescer)(*SQLFenceController,error){return cyberpanel.NewSQLFenceController(database,quiescer)}

type ExtractorOperation = cyberpanel.ExtractorOperation
type ExtractorRequest = cyberpanel.ExtractorRequest
type ExtractorResponse = cyberpanel.ExtractorResponse
type PeerAuthorizer = cyberpanel.PeerAuthorizer
type PinnedTLSAuthorizer = cyberpanel.PinnedTLSAuthorizer
type ServerConfig = cyberpanel.ServerConfig
type Server = cyberpanel.Server
type DialContext = cyberpanel.DialContext
type Client = cyberpanel.Client
func NewServer(config ServerConfig)(*Server,error){return cyberpanel.NewServer(config)}
func NewClient(dial DialContext,maximumResponseBytes uint32,timeout time.Duration)(*Client,error){return cyberpanel.NewClient(dial,maximumResponseBytes,timeout)}
func NewPinnedTLSAuthorizer(allowedSPKI []string)(*PinnedTLSAuthorizer,error){return cyberpanel.NewPinnedTLSAuthorizer(allowedSPKI)}

var _ migration.SourceReader=(*Extractor)(nil)
