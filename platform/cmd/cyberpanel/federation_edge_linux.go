//go:build linux

package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

const (
	localFederationNodeID federation.ID = "local"
	federationEnrollmentTTL              = 15 * time.Minute
)

const federationEnrollmentSchema = `
CREATE TABLE IF NOT EXISTS federation_enrollment_tokens(
 id TEXT PRIMARY KEY,
 peer_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 token_digest TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL CHECK(state IN ('pending','consumed','expired')),
 token_json BLOB NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 consumed_at TIMESTAMP,
 created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS federation_enrollment_node_created ON federation_enrollment_tokens(node_id,created_at);
CREATE UNIQUE INDEX IF NOT EXISTS federation_enrollment_node_pending ON federation_enrollment_tokens(node_id) WHERE state='pending';
`

type federationEnrollmentRepository struct {
	db  *sql.DB
	now func() time.Time
}

func newFederationEnrollmentRepository(ctx context.Context, db *sql.DB, now func() time.Time) (*federationEnrollmentRepository, error) {
	if ctx == nil || db == nil {
		return nil, federation.ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	repository := &federationEnrollmentRepository{db: db, now: now}
	if _, err := db.ExecContext(ctx, federationEnrollmentSchema); err != nil {
		return nil, err
	}
	return repository, nil
}

func (repository *federationEnrollmentRepository) Create(ctx context.Context, token federation.EnrollmentToken) error {
	if repository == nil || repository.db == nil || ctx == nil {
		return federation.ErrInvalid
	}
	encoded, err := json.Marshal(token)
	if err != nil {
		return err
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := repository.now().UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE federation_enrollment_tokens SET state='expired' WHERE node_id=? AND state='pending' AND expires_at<=?`, token.NodeID, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO federation_enrollment_tokens(id,peer_id,node_id,token_digest,state,token_json,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`, token.ID, token.PeerID, token.NodeID, token.TokenDigest, "pending", encoded, token.ExpiresAt, now); err != nil {
		var conflicts uint64
		if conflictErr := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM federation_enrollment_tokens WHERE id=? OR token_digest=? OR (node_id=? AND state='pending')`, token.ID, token.TokenDigest, token.NodeID).Scan(&conflicts); conflictErr == nil && conflicts > 0 {
			return federation.ErrConflict
		}
		return err
	}
	return tx.Commit()
}

func (repository *federationEnrollmentRepository) Consume(ctx context.Context, id federation.ID, tokenDigest string, now time.Time) (federation.EnrollmentToken, error) {
	if repository == nil || repository.db == nil || ctx == nil || !id.Valid() || len(tokenDigest) != 64 || now.IsZero() {
		return federation.EnrollmentToken{}, federation.ErrInvalid
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil {
		return federation.EnrollmentToken{}, err
	}
	defer tx.Rollback()
	var encoded []byte
	var storedDigest, state string
	var expiresAt time.Time
	if err = tx.QueryRowContext(ctx, `SELECT token_digest,state,token_json,expires_at FROM federation_enrollment_tokens WHERE id=?`, id).Scan(&storedDigest, &state, &encoded, &expiresAt); errors.Is(err, sql.ErrNoRows) {
		return federation.EnrollmentToken{}, federation.ErrNotFound
	} else if err != nil {
		return federation.EnrollmentToken{}, err
	}
	if subtle.ConstantTimeCompare([]byte(storedDigest), []byte(tokenDigest)) != 1 {
		return federation.EnrollmentToken{}, federation.ErrForbidden
	}
	if state == "expired" {
		return federation.EnrollmentToken{}, federation.ErrExpired
	}
	if state != "pending" {
		return federation.EnrollmentToken{}, federation.ErrReplay
	}
	if !now.Before(expiresAt) {
		return federation.EnrollmentToken{}, federation.ErrExpired
	}
	result, err := tx.ExecContext(ctx, `UPDATE federation_enrollment_tokens SET state='consumed',consumed_at=? WHERE id=? AND state='pending'`, now.UTC(), id)
	if err != nil {
		return federation.EnrollmentToken{}, err
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return federation.EnrollmentToken{}, federation.ErrConflict
	}
	var token federation.EnrollmentToken
	if err = json.Unmarshal(encoded, &token); err != nil {
		return federation.EnrollmentToken{}, err
	}
	consumedAt := now.UTC()
	token.ConsumedAt = &consumedAt
	if err = tx.Commit(); err != nil {
		return federation.EnrollmentToken{}, err
	}
	return token, nil
}

func (repository *federationEnrollmentRepository) latest(ctx context.Context, node federation.ID) (federation.EnrollmentToken, bool, error) {
	if repository == nil || repository.db == nil || ctx == nil || !node.Valid() {
		return federation.EnrollmentToken{}, false, federation.ErrInvalid
	}
	var encoded []byte
	var consumedAt sql.NullTime
	err := repository.db.QueryRowContext(ctx, `SELECT token_json,consumed_at FROM federation_enrollment_tokens WHERE node_id=? ORDER BY created_at DESC,id DESC LIMIT 1`, node).Scan(&encoded, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return federation.EnrollmentToken{}, false, nil
	}
	if err != nil {
		return federation.EnrollmentToken{}, false, err
	}
	var token federation.EnrollmentToken
	if err = json.Unmarshal(encoded, &token); err != nil {
		return federation.EnrollmentToken{}, false, err
	}
	if consumedAt.Valid {
		value := consumedAt.Time.UTC()
		token.ConsumedAt = &value
	}
	return token, true, nil
}

type federationEdge struct {
	store       *federation.Store
	enrollments *federationEnrollmentRepository
	preparer    *federation.EnrollmentPreparer
	materials   *federationEnrollmentMaterials
	authority   *federation.LocalAuthority
	buildDigest string
	now         func() time.Time
}

func newFederationEdge(ctx context.Context, db *sql.DB, now func() time.Time) (*federationEdge, error) {
	if ctx == nil || db == nil {
		return nil, federation.ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	store, err := federation.NewStore(db)
	if err != nil {
		return nil, err
	}
	if err = store.Bootstrap(ctx, localFederationNodeID); err != nil {
		return nil, err
	}
	enrollments, err := newFederationEnrollmentRepository(ctx, db, now)
	if err != nil {
		return nil, err
	}
	preparer, err := federation.NewEnrollmentPreparer(enrollments)
	if err != nil {
		return nil, err
	}
	authority, err := federation.NewLocalAuthority(store)
	if err != nil {
		return nil, err
	}
	materials, buildDigest, err := newFederationEnrollmentMaterials(ctx, db, now)
	if err != nil {
		return nil, err
	}
	return &federationEdge{store: store, enrollments: enrollments, preparer: preparer, materials: materials, authority: authority, buildDigest: buildDigest, now: now}, nil
}

func (edge *federationEdge) ListNodes(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.FleetNodeProjection], error) {
	if err := edge.validateCall(ctx, call, identity.AssurancePassword, false); err != nil || call.ResourceID != "" {
		return apiserver.EdgePage[apiserver.FleetNodeProjection]{}, federationAPIError(firstFederationError(err, federation.ErrInvalid))
	}
	projection, err := edge.projection(ctx)
	if err != nil {
		return apiserver.EdgePage[apiserver.FleetNodeProjection]{}, federationAPIError(err)
	}
	if page.Cursor != "" {
		if page.Cursor != projection.ID {
			return apiserver.EdgePage[apiserver.FleetNodeProjection]{}, apiserver.ErrInvalidRequest
		}
		return apiserver.EdgePage[apiserver.FleetNodeProjection]{Items: []apiserver.FleetNodeProjection{}, Total: 1}, nil
	}
	return apiserver.EdgePage[apiserver.FleetNodeProjection]{Items: []apiserver.FleetNodeProjection{projection}, Total: 1}, nil
}

func (edge *federationEdge) GetNode(ctx context.Context, call apiserver.EdgeCall) (apiserver.FleetNodeProjection, error) {
	if err := edge.validateCall(ctx, call, identity.AssurancePassword, false); err != nil {
		return apiserver.FleetNodeProjection{}, federationAPIError(err)
	}
	projection, err := edge.projection(ctx)
	if err != nil {
		return apiserver.FleetNodeProjection{}, federationAPIError(err)
	}
	if call.ResourceID != projection.ID {
		return apiserver.FleetNodeProjection{}, apiserver.ErrNotFound
	}
	return projection, nil
}

func (edge *federationEdge) EnrollNode(ctx context.Context, call apiserver.EdgeCall, payload apiserver.FleetEnrollPayload, token []byte) (apiserver.EdgeMutation[apiserver.FleetNodeProjection], error) {
	defer wipeFederationEnrollmentBytes(token)
	if err := edge.validateCall(ctx, call, identity.AssuranceMFA, true); err != nil || call.ResourceID != "" || call.ExpectedGeneration != 0 || len(token) < 32 {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(firstFederationError(err, federation.ErrInvalid))
	}
	node, authorityEpoch, activePeer, err := edge.store.State(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(err)
	}
	if activePeer != "" {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, apiserver.ErrConflict
	}
	if pending, found, loadErr := edge.enrollments.latest(ctx, node); loadErr != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(loadErr)
	} else if found && pending.ConsumedAt == nil && edge.now().UTC().Before(pending.ExpiresAt) {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, apiserver.ErrConflict
	}
	peer, err := federation.NewID(payload.PeerID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, apiserver.ErrInvalidRequest
	}
	endpoint, err := normalizedFederationEndpoint(payload.CentralEndpoint)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, apiserver.ErrInvalidRequest
	}
	tokenID, err := federation.NewID(call.CommandID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, apiserver.ErrInvalidRequest
	}
	if err = edge.materials.begin(node, payload.CentralFingerprint); err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(err)
	}
	preparationToken := append([]byte(nil), token...)
	if _, err = edge.preparer.Prepare(ctx, tokenID, peer, node, preparationToken, payload.CentralFingerprint, endpoint, federationEnrollmentTTL); err != nil {
		cleanupErr := edge.materials.cleanup(ctx, node)
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(errors.Join(err, cleanupErr))
	}
	exchange, err := newFederationEnrollmentHTTPExchange(endpoint, peer, payload.CentralFingerprint, edge.now)
	if err != nil {
		cleanupErr := edge.materials.cleanup(ctx, node)
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(errors.Join(err, cleanupErr))
	}
	enrollment, err := federation.NewEnrollmentService(edge.enrollments, edge.materials, edge.materials, exchange, edge.store)
	if err != nil {
		cleanupErr := edge.materials.cleanup(ctx, node)
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(errors.Join(err, cleanupErr))
	}
	capabilities := federation.CapabilitySet{
		NodeID: node, ProtocolVersion: federationEnrollmentProtocolVersion, BuildDigest: edge.buildDigest,
		OS: runtime.GOOS, Architecture: runtime.GOARCH, AuthorityEpoch: authorityEpoch,
		Capabilities: []federation.Capability{}, GeneratedAt: edge.now().UTC(),
	}
	capabilities.Digest = capabilities.CanonicalDigest()
	if _, err = enrollment.Enroll(ctx, tokenID, token, capabilities); err != nil {
		cleanupErr := edge.materials.cleanup(ctx, node)
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(errors.Join(err, cleanupErr))
	}
	edge.materials.finish(node)
	projection, err := edge.projection(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(err)
	}
	return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{OperationID: call.CommandID, State: projection.State, Generation: projection.Generation, Resource: projection}, nil
}

func (edge *federationEdge) RevokeNode(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.FleetNodeProjection], error) {
	if err := edge.validateCall(ctx, call, identity.AssurancePhishingResistant, true); err != nil || call.ResourceID == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(firstFederationError(err, federation.ErrInvalid))
	}
	node, epoch, activePeer, err := edge.store.State(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(err)
	}
	if call.ResourceID != node.String() {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, apiserver.ErrNotFound
	}
	if activePeer == "" || call.ExpectedGeneration != epoch {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, apiserver.ErrConflict
	}
	if err = edge.authority.Revoke(ctx, "local-owner-revoke"); err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(err)
	}
	projection, err := edge.projection(ctx)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{}, federationAPIError(err)
	}
	return apiserver.EdgeMutation[apiserver.FleetNodeProjection]{OperationID: call.CommandID, State: projection.State, Generation: projection.Generation, Resource: projection}, nil
}

func (edge *federationEdge) validateCall(ctx context.Context, call apiserver.EdgeCall, minimum identity.AssuranceLevel, mutating bool) error {
	if edge == nil || edge.store == nil || edge.enrollments == nil || edge.preparer == nil || edge.materials == nil || edge.authority == nil || ctx == nil || call.TenantID != "" || call.CommandID == "" || call.PrincipalID == "" || call.CredentialID == "" || call.AuthzEpoch == 0 || call.Assurance < minimum {
		return federation.ErrForbidden
	}
	if !mutating && call.ExpectedGeneration != 0 {
		return federation.ErrInvalid
	}
	return nil
}

func (edge *federationEdge) projection(ctx context.Context) (apiserver.FleetNodeProjection, error) {
	node, epoch, activePeer, err := edge.store.State(ctx)
	if err != nil {
		return apiserver.FleetNodeProjection{}, err
	}
	projection := apiserver.FleetNodeProjection{ID: node.String(), Name: "Local node", State: "standalone", Architecture: runtime.GOARCH, AuthorityEpoch: epoch, Generation: epoch}
	pending, found, err := edge.enrollments.latest(ctx, node)
	if err != nil {
		return apiserver.FleetNodeProjection{}, err
	}
	if found {
		projection.PeerID = pending.PeerID.String()
		projection.CentralEndpoint = pending.Endpoint
		projection.CAFingerprint = pending.CAFingerprint
		projection.EnrollmentExpiresAt = pending.ExpiresAt
	}
	if activePeer != "" {
		peer, loadErr := edge.store.Peer(ctx, activePeer)
		if loadErr != nil {
			return apiserver.FleetNodeProjection{}, loadErr
		}
		projection.PeerID = peer.ID.String()
		projection.State = peer.State
		projection.CAFingerprint = peer.CAFingerprint
		projection.UpdatedAt = peer.UpdatedAt
		return projection, nil
	}
	if found {
		switch {
		case pending.ConsumedAt != nil:
			projection.State = "enrollment_consumed"
			if _, peerErr := edge.store.Peer(ctx, pending.PeerID); peerErr == nil {
				projection.State = "revoked"
			} else if !errors.Is(peerErr, federation.ErrNotFound) {
				return apiserver.FleetNodeProjection{}, peerErr
			}
			projection.UpdatedAt = pending.ConsumedAt.UTC()
		case edge.now().UTC().Before(pending.ExpiresAt):
			projection.State = "enrollment_pending"
		case !pending.ExpiresAt.IsZero():
			projection.State = "enrollment_expired"
			projection.UpdatedAt = pending.ExpiresAt.UTC()
		}
	}
	return projection, nil
}

func normalizedFederationEndpoint(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return "", federation.ErrInvalid
	}
	return parsed.String(), nil
}

func federationAPIError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, federation.ErrInvalid):
		return apiserver.ErrInvalidRequest
	case errors.Is(err, federation.ErrForbidden):
		return apiserver.ErrForbidden
	case errors.Is(err, federation.ErrNotFound):
		return apiserver.ErrNotFound
	case errors.Is(err, federation.ErrExpired), errors.Is(err, federation.ErrStale), errors.Is(err, federation.ErrReplay), errors.Is(err, federation.ErrConflict):
		return apiserver.ErrConflict
	case errors.Is(err, federation.ErrOffline), errors.Is(err, federation.ErrAmbiguous):
		return apiserver.ErrUnavailable
	default:
		return err
	}
}

func firstFederationError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}

var _ federation.EnrollmentStore = (*federationEnrollmentRepository)(nil)
var _ apiserver.FleetEdgeService = (*federationEdge)(nil)
