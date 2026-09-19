package federation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	SnapshotMaximumRows = 10000
	SnapshotMaximumBytes = 32 << 20
	SnapshotMaximumChunkBytes = 512 << 10
	SnapshotMaximumChunks = 128
)

const snapshotSchema = `
CREATE TABLE IF NOT EXISTS federation_projection_source_v1(singleton_id INTEGER PRIMARY KEY,complete INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS federation_projection_latest_v1(resource_kind TEXT NOT NULL,resource_id TEXT NOT NULL,event_json BLOB NOT NULL,generation BIGINT NOT NULL,event_sequence BIGINT NOT NULL,PRIMARY KEY(resource_kind,resource_id));
CREATE TABLE IF NOT EXISTS federation_projection_snapshots_v1(snapshot_id TEXT NOT NULL,chunk_index INTEGER NOT NULL,peer_id TEXT NOT NULL,authority_epoch BIGINT NOT NULL,generation BIGINT NOT NULL,chunk_json BLOB NOT NULL,PRIMARY KEY(snapshot_id,chunk_index));
`

var ErrProjectionSourceIncomplete = errors.New("federation: projection source has incomplete retained history")

type ProjectionSnapshotRequest struct {
	SnapshotID ID `json:"snapshotId"`
	NodeID ID `json:"nodeId"`
	PeerID ID `json:"peerId"`
	AuthorityEpoch uint64 `json:"authorityEpoch"`
	ExpectedSequence uint64 `json:"expectedSequence"`
	ReceivedSequence uint64 `json:"receivedSequence"`
	SnapshotGeneration uint64 `json:"snapshotGeneration"`
	NextChunk uint32 `json:"nextChunk"`
	Reason string `json:"reason"`
}

func (request ProjectionSnapshotRequest) Digest() string {
	request.NextChunk = 0
	encoded, _ := json.Marshal(request)
	return digest(encoded)
}

type SnapshotProjection struct {
	TenantID string `json:"tenantId"`
	ResourceKind string `json:"resourceKind"`
	ResourceID string `json:"resourceId"`
	Generation uint64 `json:"generation"`
	EventSequence uint64 `json:"eventSequence"`
	Payload json.RawMessage `json:"payload"`
	PayloadDigest string `json:"payloadDigest"`
	ObservedAt time.Time `json:"observedAt"`
}

type ProjectionSnapshotChunk struct {
	SnapshotID ID `json:"snapshotId"`
	NodeID ID `json:"nodeId"`
	PeerID ID `json:"peerId"`
	AuthorityEpoch uint64 `json:"authorityEpoch"`
	SnapshotGeneration uint64 `json:"snapshotGeneration"`
	Watermark uint64 `json:"watermark"`
	Index uint32 `json:"index"`
	Total uint32 `json:"total"`
	ManifestDigest string `json:"manifestDigest"`
	RequestDigest string `json:"requestDigest"`
	Baseline *ProjectionBaselineEvidence `json:"baseline,omitempty"`
	Rows []SnapshotProjection `json:"rows"`
	SignatureKeyID string `json:"signatureKeyId"`
	Signature []byte `json:"signature"`
}

func (chunk ProjectionSnapshotChunk) Content() []byte {
	chunk.Signature, chunk.SignatureKeyID = nil, ""
	encoded, _ := json.Marshal(chunk)
	return encoded
}

func (chunk ProjectionSnapshotChunk) SigStructure() []byte {
	chunk.Signature = nil
	encoded, _ := json.Marshal(struct { Domain string `json:"domain"`; Chunk ProjectionSnapshotChunk `json:"chunk"` }{"cyberpanel-projection-snapshot-chunk-v1", chunk})
	return encoded
}

func SnapshotManifestDigest(rows []SnapshotProjection) string {
	encoded, _ := json.Marshal(rows)
	return digest(encoded)
}

func (row SnapshotProjection) Validate(watermark uint64, now time.Time) error {
	if row.ResourceKind == "" || len(row.ResourceKind)>256 || row.ResourceID == "" || len(row.ResourceID)>256 || len(row.TenantID)>256 || strings.ContainsAny(row.ResourceKind+row.ResourceID+row.TenantID,"\x00\r\n") || row.EventSequence == 0 || row.EventSequence > watermark || len(row.Payload)==0 || len(row.Payload)>SnapshotMaximumChunkBytes/2 || !json.Valid(row.Payload) || row.PayloadDigest!=digest(row.Payload) || row.ObservedAt.IsZero() || row.ObservedAt.After(now.Add(5*time.Minute)) {
		return ErrInvalid
	}
	return nil
}

// Legacy event continuity can never establish authoritative absence. Only a
// complete control-authority scan performed by PublishProjection flips this
// source bit after its resource events and marker are durably enqueued.
func (s *Store) bootstrapProjectionSourceTx(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO federation_projection_source_v1(singleton_id,complete) VALUES(1,0) ON CONFLICT(singleton_id) DO NOTHING`)
	return err
}

func (s *Store) recordProjectionTx(ctx context.Context, tx *sql.Tx, event NodeEvent) error {
	if event.ResourceKind=="" && event.ResourceID=="" { return nil }
	if event.ResourceKind=="" || event.ResourceID=="" || event.Sequence==0{return ErrInvalid}
	encoded,err:=json.Marshal(event);if err!=nil{return err}
	_,err=tx.ExecContext(ctx,`INSERT INTO federation_projection_latest_v1(resource_kind,resource_id,event_json,generation,event_sequence) VALUES(?,?,?,?,?) ON CONFLICT(resource_kind,resource_id) DO UPDATE SET event_json=excluded.event_json,generation=excluded.generation,event_sequence=excluded.event_sequence WHERE excluded.generation>=federation_projection_latest_v1.generation AND excluded.event_sequence>federation_projection_latest_v1.event_sequence`,event.ResourceKind,event.ResourceID,encoded,event.Generation,event.Sequence)
	return err
}

func (s *Store) ProjectionSnapshotChunk(ctx context.Context, request ProjectionSnapshotRequest) (ProjectionSnapshotChunk,error) {
	var chunk ProjectionSnapshotChunk
	if s==nil||s.db==nil||ctx==nil||!request.SnapshotID.Valid()||!request.NodeID.Valid()||!request.PeerID.Valid()||request.AuthorityEpoch==0||request.ExpectedSequence==0||request.SnapshotGeneration==0||request.NextChunk>=SnapshotMaximumChunks{return chunk,ErrInvalid}
	tx,err:=s.db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return chunk,err};defer tx.Rollback()
	var node,peer ID;var epoch uint64
	if err=tx.QueryRowContext(ctx,`SELECT node_id,active_peer_id,authority_epoch FROM federation_state WHERE singleton_id=1`).Scan(&node,&peer,&epoch);err!=nil{return chunk,err}
	if node!=request.NodeID||peer!=request.PeerID||epoch!=request.AuthorityEpoch{return chunk,ErrStale}
	ready,readyErr:=projectionBaselineReadyTx(ctx,tx,node,epoch);if readyErr!=nil{return chunk,readyErr};if !ready{return chunk,errors.Join(ErrStale,ErrProjectionSourceIncomplete)}
	var raw []byte
	err=tx.QueryRowContext(ctx,`SELECT chunk_json FROM federation_projection_snapshots_v1 WHERE snapshot_id=? AND chunk_index=?`,request.SnapshotID,request.NextChunk).Scan(&raw)
	if err==nil{
		if json.Unmarshal(raw,&chunk)!=nil||chunk.NodeID!=node||chunk.PeerID!=peer||chunk.AuthorityEpoch!=epoch||chunk.SnapshotGeneration!=request.SnapshotGeneration||chunk.RequestDigest!=request.Digest(){return chunk,ErrReplay}
		return chunk,tx.Commit()
	}
	if !errors.Is(err,sql.ErrNoRows){return chunk,err}
	if request.NextChunk!=0{return chunk,ErrNotFound}
	var watermark uint64
	if err=tx.QueryRowContext(ctx,`SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='federation_events'),0)`).Scan(&watermark);err!=nil{return chunk,err}
	if watermark<request.ExpectedSequence-1||watermark<request.ReceivedSequence{return chunk,ErrStale}
	var baselineSequence uint64;var baselineJSON []byte;var baselineEvent NodeEvent
	if err=tx.QueryRowContext(ctx,`SELECT sequence,payload_json FROM federation_events WHERE kind=? AND sequence<=? ORDER BY sequence DESC LIMIT 1`,ProjectionBaselineCompleteEventKind,watermark).Scan(&baselineSequence,&baselineJSON);err!=nil{return chunk,errors.Join(ErrProjectionSourceIncomplete,err)}
	if json.Unmarshal(baselineJSON,&baselineEvent)!=nil{return chunk,ErrInvalid};baselineEvent.Sequence=baselineSequence
	baseline,attestation,baselineErr:=ProjectionBaselineEvidenceFromEvent(baselineEvent);if baselineErr!=nil||attestation.NodeID!=node||attestation.AuthorityEpoch!=epoch{return chunk,errors.Join(ErrProjectionSourceIncomplete,baselineErr)}
	rows,err:=tx.QueryContext(ctx,`SELECT event_json FROM federation_projection_latest_v1 ORDER BY resource_kind,resource_id LIMIT ?`,SnapshotMaximumRows+1);if err!=nil{return chunk,err}
	projections:=[]SnapshotProjection{}
	bytesUsed:=0
	for rows.Next(){
		var encoded []byte;var event NodeEvent
		if err=rows.Scan(&encoded);err!=nil{rows.Close();return chunk,err}
		if json.Unmarshal(encoded,&event)!=nil||event.NodeID!=node{rows.Close();return chunk,ErrInvalid}
		row:=SnapshotProjection{event.TenantID,event.ResourceKind,event.ResourceID,event.Generation,event.Sequence,event.Payload,event.PayloadDigest,event.OccurredAt}
		if row.Validate(watermark,s.clock().UTC())!=nil{rows.Close();return chunk,ErrInvalid}
		bytesUsed+=len(encoded);projections=append(projections,row)
		if len(projections)>SnapshotMaximumRows||bytesUsed>SnapshotMaximumBytes{rows.Close();return chunk,ErrInvalid}
	}
	err=rows.Err();rows.Close();if err!=nil{return chunk,err}
	if ValidateProjectionBaselineState(attestation,baseline.EventSequence,projections)!=nil{return chunk,ErrProjectionSourceIncomplete}
	digest:=SnapshotManifestDigest(projections)
	chunks:=[]ProjectionSnapshotChunk{}
	current:=ProjectionSnapshotChunk{SnapshotID:request.SnapshotID,NodeID:node,PeerID:peer,AuthorityEpoch:epoch,SnapshotGeneration:request.SnapshotGeneration,Watermark:watermark,ManifestDigest:digest,RequestDigest:request.Digest(),Baseline:&baseline,Rows:[]SnapshotProjection{}}
	for _,row:=range projections{
		candidate:=current;candidate.Rows=append(append([]SnapshotProjection(nil),current.Rows...),row)
		if len(candidate.Content())>SnapshotMaximumChunkBytes-2048 {
			if len(current.Rows)==0{return chunk,ErrInvalid};chunks=append(chunks,current);current.Rows=[]SnapshotProjection{row};current.Baseline=nil
		}else{current=candidate}
	}
	chunks=append(chunks,current)
	if len(chunks)>SnapshotMaximumChunks{return chunk,ErrInvalid}
	// Retain only the current generation; central cannot request a successor
	// until it has atomically applied its predecessor.
	if _,err=tx.ExecContext(ctx,`DELETE FROM federation_projection_snapshots_v1 WHERE generation<? OR peer_id<>? OR authority_epoch<>?`,request.SnapshotGeneration,peer,epoch);err!=nil{return chunk,err}
	var retained int
	if err=tx.QueryRowContext(ctx,`SELECT COUNT(DISTINCT snapshot_id) FROM federation_projection_snapshots_v1`).Scan(&retained);err!=nil{return chunk,err}
	if retained>=2{return chunk,ErrConflict}
	for index:=range chunks{
		chunks[index].Index=uint32(index);chunks[index].Total=uint32(len(chunks));encoded:=chunks[index].Content()
		if _,err=tx.ExecContext(ctx,`INSERT INTO federation_projection_snapshots_v1(snapshot_id,chunk_index,peer_id,authority_epoch,generation,chunk_json) VALUES(?,?,?,?,?,?)`,request.SnapshotID,index,peer,epoch,request.SnapshotGeneration,encoded);err!=nil{return chunk,err}
	}
	return chunks[0],tx.Commit()
}
