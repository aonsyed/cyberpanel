package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const projectionSnapshotSchema = `
CREATE TABLE IF NOT EXISTS fleet_projection_snapshots_v1(node_id TEXT PRIMARY KEY,request_json BLOB NOT NULL,state TEXT NOT NULL,next_chunk INTEGER NOT NULL,total_chunks INTEGER NOT NULL,watermark BIGINT NOT NULL,manifest_digest TEXT NOT NULL,received_bytes BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS fleet_projection_snapshot_chunks_v1(node_id TEXT NOT NULL,chunk_index INTEGER NOT NULL,chunk_json BLOB NOT NULL,PRIMARY KEY(node_id,chunk_index));
CREATE TABLE IF NOT EXISTS fleet_projection_snapshot_receipts_v1(node_id TEXT PRIMARY KEY,generation BIGINT NOT NULL,watermark BIGINT NOT NULL,manifest_digest TEXT NOT NULL);
`

func (s *Store) BeginProjectionSnapshot(ctx context.Context, nodeID, peerID federation.ID, epoch, received uint64) (federation.ProjectionSnapshotRequest,error) {
	var request federation.ProjectionSnapshotRequest
	if s==nil||s.db==nil||ctx==nil||!nodeID.Valid()||!peerID.Valid()||epoch==0{return request,ErrInvalid}
	tx,err:=s.db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return request,err};defer tx.Rollback()
	node,err:=loadNodeTx(ctx,tx,nodeID);if err!=nil{return request,err}
	if node.AuthorityEpoch!=epoch||node.State==NodeRevoking||node.State==NodeRevoked||node.SnapshotGeneration>=1<<63-1||node.ProjectionSequence>=1<<63-1{return request,ErrStale}
	var raw []byte;var state string;var next uint32
	err=tx.QueryRowContext(ctx,`SELECT request_json,state,next_chunk FROM fleet_projection_snapshots_v1 WHERE node_id=?`,nodeID).Scan(&raw,&state,&next)
	if err==nil&&state=="receiving"{
		if json.Unmarshal(raw,&request)!=nil||request.NodeID!=nodeID{return request,ErrStale}
		if request.PeerID==peerID&&request.AuthorityEpoch==epoch&&request.SnapshotGeneration==node.SnapshotGeneration+1 {
			request.NextChunk=next;return request,tx.Commit()
		}
	}
	if err!=nil&&!errors.Is(err,sql.ErrNoRows){return request,err}
	identifier:=digest([]byte(fmt.Sprintf("cyberpanel-projection-snapshot-v1\x00%s\x00%s\x00%d\x00%d\x00%d",nodeID,peerID,epoch,node.SnapshotGeneration+1,node.ProjectionSequence)))
	request=federation.ProjectionSnapshotRequest{SnapshotID:federation.ID("snapshot_"+identifier[:48]),NodeID:nodeID,PeerID:peerID,AuthorityEpoch:epoch,ExpectedSequence:node.ProjectionSequence+1,ReceivedSequence:received,SnapshotGeneration:node.SnapshotGeneration+1,Reason:"event_sequence_gap"}
	raw,err=json.Marshal(request);if err!=nil{return request,err}
	if _,err=tx.ExecContext(ctx,`DELETE FROM fleet_projection_snapshot_chunks_v1 WHERE node_id=?`,nodeID);err!=nil{return request,err}
	_,err=tx.ExecContext(ctx,`INSERT INTO fleet_projection_snapshots_v1(node_id,request_json,state,next_chunk,total_chunks,watermark,manifest_digest,received_bytes) VALUES(?,?,'receiving',0,0,0,'',0) ON CONFLICT(node_id) DO UPDATE SET request_json=excluded.request_json,state='receiving',next_chunk=0,total_chunks=0,watermark=0,manifest_digest='',received_bytes=0`,nodeID,raw)
	if err!=nil{return request,err}
	if _,err=tx.ExecContext(ctx,`UPDATE fleet_projections SET stale=1 WHERE node_id=?`,nodeID);err!=nil{return request,err}
	return request,tx.Commit()
}

func (s *Store) PendingProjectionSnapshot(ctx context.Context, nodeID federation.ID, peerID federation.ID, epoch uint64) (federation.ProjectionSnapshotRequest,bool,error) {
	var request federation.ProjectionSnapshotRequest;var raw []byte;var next uint32
	err:=s.db.QueryRowContext(ctx,`SELECT request_json,next_chunk FROM fleet_projection_snapshots_v1 WHERE node_id=? AND state='receiving'`,nodeID).Scan(&raw,&next)
	if errors.Is(err,sql.ErrNoRows){return request,false,nil};if err!=nil{return request,false,err}
	if json.Unmarshal(raw,&request)!=nil||request.NodeID!=nodeID{return request,false,ErrStale}
	if request.PeerID!=peerID||request.AuthorityEpoch!=epoch{return request,false,nil}
	request.NextChunk=next;return request,true,nil
}

func (s *Store) ReceiveProjectionSnapshot(ctx context.Context, chunk federation.ProjectionSnapshotChunk, certificateFingerprint string) (federation.ProjectionSnapshotRequest,bool,error) {
	var request federation.ProjectionSnapshotRequest
	content:=chunk.Content()
	if s==nil||s.db==nil||ctx==nil||!chunk.SnapshotID.Valid()||!chunk.NodeID.Valid()||!chunk.PeerID.Valid()||chunk.AuthorityEpoch==0||chunk.SnapshotGeneration==0||chunk.Total==0||chunk.Total>federation.SnapshotMaximumChunks||chunk.Index>=chunk.Total||len(content)>federation.SnapshotMaximumChunkBytes||!validSHA256(chunk.ManifestDigest)||!validSHA256(certificateFingerprint){return request,false,ErrInvalid}
	tx,err:=s.db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return request,false,err};defer tx.Rollback()
	node,err:=loadNodeTx(ctx,tx,chunk.NodeID);if err!=nil{return request,false,err}
	if node.AuthorityEpoch!=chunk.AuthorityEpoch||node.CertificateFingerprint!=certificateFingerprint||node.State==NodeRevoking||node.State==NodeRevoked{return request,false,ErrStale}
	var raw []byte;var state,manifest string;var next,total uint32;var watermark uint64;var receivedBytes int
	err=tx.QueryRowContext(ctx,`SELECT request_json,state,next_chunk,total_chunks,watermark,manifest_digest,received_bytes FROM fleet_projection_snapshots_v1 WHERE node_id=?`,node.ID).Scan(&raw,&state,&next,&total,&watermark,&manifest,&receivedBytes)
	if err!=nil{return request,false,err}
	if json.Unmarshal(raw,&request)!=nil||request.SnapshotID!=chunk.SnapshotID||request.NodeID!=chunk.NodeID||request.PeerID!=chunk.PeerID||request.AuthorityEpoch!=chunk.AuthorityEpoch||request.SnapshotGeneration!=chunk.SnapshotGeneration||request.Digest()!=chunk.RequestDigest{return request,false,ErrStale}
	if chunk.Watermark<request.ExpectedSequence-1||chunk.Watermark<request.ReceivedSequence{return request,false,ErrStale}
	if total!=0&&(total!=chunk.Total||watermark!=chunk.Watermark||manifest!=chunk.ManifestDigest){return request,false,ErrConflict}
	for _,row:=range chunk.Rows{if row.Validate(chunk.Watermark,s.clock().UTC())!=nil{return request,false,ErrInvalid}}
	if chunk.Index<next {
		var existing []byte
		if err=tx.QueryRowContext(ctx,`SELECT chunk_json FROM fleet_projection_snapshot_chunks_v1 WHERE node_id=? AND chunk_index=?`,node.ID,chunk.Index).Scan(&existing);err!=nil{return request,false,err}
		if !bytes.Equal(existing,content){return request,false,ErrConflict}
		request.NextChunk=next;return request,state=="applied",tx.Commit()
	}
	if state!="receiving"||chunk.Index!=next||node.SnapshotGeneration+1!=chunk.SnapshotGeneration||node.ProjectionSequence+1!=request.ExpectedSequence{return request,false,ErrStale}
	if receivedBytes+len(content)>federation.SnapshotMaximumBytes{return request,false,ErrInvalid}
	if _,err=tx.ExecContext(ctx,`INSERT INTO fleet_projection_snapshot_chunks_v1(node_id,chunk_index,chunk_json) VALUES(?,?,?)`,node.ID,chunk.Index,content);err!=nil{return request,false,err}
	next++
	_,err=tx.ExecContext(ctx,`UPDATE fleet_projection_snapshots_v1 SET next_chunk=?,total_chunks=?,watermark=?,manifest_digest=?,received_bytes=? WHERE node_id=? AND state='receiving'`,next,chunk.Total,chunk.Watermark,chunk.ManifestDigest,receivedBytes+len(content),node.ID)
	if err!=nil{return request,false,err}
	request.NextChunk=next
	if next<chunk.Total{return request,false,tx.Commit()}
	rows,err:=tx.QueryContext(ctx,`SELECT chunk_json FROM fleet_projection_snapshot_chunks_v1 WHERE node_id=? ORDER BY chunk_index`,node.ID);if err!=nil{return request,false,err}
	projections:=[]federation.SnapshotProjection{};var count uint32;previousKey:=""
	for rows.Next(){
		var encoded []byte;var stored federation.ProjectionSnapshotChunk
		if err=rows.Scan(&encoded);err!=nil{rows.Close();return request,false,err}
		if json.Unmarshal(encoded,&stored)!=nil||stored.Index!=count||stored.Total!=chunk.Total||stored.Watermark!=chunk.Watermark||stored.ManifestDigest!=chunk.ManifestDigest{rows.Close();return request,false,ErrConflict}
		for _,row:=range stored.Rows{
			key:=row.ResourceKind+"\x00"+row.ResourceID
			if key<=previousKey||len(projections)>=federation.SnapshotMaximumRows{rows.Close();return request,false,ErrInvalid}
			previousKey=key;projections=append(projections,row)
		}
		count++
	}
	err=rows.Err();rows.Close();if err!=nil{return request,false,err}
	if count!=chunk.Total||federation.SnapshotManifestDigest(projections)!=chunk.ManifestDigest{return request,false,ErrConflict}
	// Replacement is observation-only. Node-local resource specifications and
	// mutation grants are not touched, and no health/resource row is invented.
	if _,err=tx.ExecContext(ctx,`DELETE FROM fleet_projections WHERE node_id=?`,node.ID);err!=nil{return request,false,err}
	for _,row:=range projections{
		_,err=tx.ExecContext(ctx,`INSERT INTO fleet_projections(node_id,tenant_id,resource_kind,resource_id,generation,status_json,digest,observed_at,event_sequence,stale) VALUES(?,?,?,?,?,?,?,?,?,0)`,node.ID,row.TenantID,row.ResourceKind,row.ResourceID,row.Generation,row.Payload,row.PayloadDigest,row.ObservedAt,row.EventSequence)
		if err!=nil{return request,false,err}
	}
	update,err:=tx.ExecContext(ctx,`UPDATE fleet_nodes SET projection_sequence=?,snapshot_generation=?,state=CASE WHEN state='degraded' THEN 'online' ELSE state END,updated_at=? WHERE id=? AND authority_epoch=? AND certificate_fingerprint=? AND projection_sequence=? AND snapshot_generation=? AND state NOT IN ('revoking','revoked')`,chunk.Watermark,chunk.SnapshotGeneration,s.clock().UTC(),node.ID,chunk.AuthorityEpoch,certificateFingerprint,node.ProjectionSequence,node.SnapshotGeneration)
	if err!=nil{return request,false,err};if affected,rowsErr:=update.RowsAffected();rowsErr!=nil||affected!=1{return request,false,ErrStale}
	if _,err=tx.ExecContext(ctx,`UPDATE fleet_projection_snapshots_v1 SET state='applied' WHERE node_id=?`,node.ID);err!=nil{return request,false,err}
	if _,err=tx.ExecContext(ctx,`INSERT INTO fleet_projection_snapshot_receipts_v1(node_id,generation,watermark,manifest_digest) VALUES(?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET generation=excluded.generation,watermark=excluded.watermark,manifest_digest=excluded.manifest_digest`,node.ID,chunk.SnapshotGeneration,chunk.Watermark,chunk.ManifestDigest);err!=nil{return request,false,err}
	return request,true,tx.Commit()
}
