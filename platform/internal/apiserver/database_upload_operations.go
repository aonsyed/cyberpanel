package apiserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

func (operations *DatabaseTransferOperations) BeginDatabaseUpload(ctx context.Context, inv Invocation, p DatabaseUploadBeginPayload) (DatabaseUploadBeginResult, error) {
	tenant, err := site.NewTenantID(inv.Request.TenantID)
	if err != nil {
		return DatabaseUploadBeginResult{}, ErrInvalidRequest
	}
	siteID, err := site.NewSiteID(inv.Request.ResourceID)
	if err != nil {
		return DatabaseUploadBeginResult{}, ErrInvalidRequest
	}
	if inv.IdempotencyKey == "" {
		return DatabaseUploadBeginResult{}, ErrInvalidRequest
	}
	digest := sha256.Sum256([]byte(inv.Request.TenantID + "\x00" + inv.Actor.PrincipalID.String() + "\x00" + commandID(inv)))
	id, _ := database.NewResourceID("upload-" + hex.EncodeToString(digest[:]))
	now := time.Now().UTC()
	intent, err := database.SealTransferUploadIntent(database.TransferUploadIntent{ID: id, TenantID: tenant, SiteID: siteID, DatabaseID: p.DatabaseID, DatabaseGeneration: inv.Request.ExpectedGeneration, CreatedBy: inv.Actor.PrincipalID.String(), Compression: p.Compression, Bytes: p.Bytes, PayloadDigest: p.Digest, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		return DatabaseUploadBeginResult{}, ErrInvalidRequest
	}
	if err = operations.authorizeUpload(ctx, inv, intent); err != nil {
		return DatabaseUploadBeginResult{}, err
	}
	intent, err = operations.persistUploadIntent(ctx, intent)
	if err != nil {
		return DatabaseUploadBeginResult{}, err
	}
	state, err := operations.ExecuteDatabaseUpload(ctx, inv, database.TransferUploadRequest{Action: "begin", Intent: intent})
	return DatabaseUploadBeginResult{Intent: intent, State: state}, err
}

func (operations *DatabaseTransferOperations) authorizeUpload(ctx context.Context, inv Invocation, intent database.TransferUploadIntent) error {
	if intent.Validate() != nil || intent.CreatedBy != inv.Actor.PrincipalID.String() || intent.TenantID.String() != inv.Request.TenantID || intent.SiteID.String() != inv.Request.ResourceID || intent.DatabaseGeneration != inv.Request.ExpectedGeneration {
		return database.ErrUnauthorized
	}
	gate := databaseTransferAuthority{operations: operations, invocation: inv}
	if err := gate.AuthorizeDatabaseTransfer(ctx, database.TransferAuthorizationRequest{Actor: intent.CreatedBy, TenantID: intent.TenantID, SiteID: intent.SiteID, DatabaseID: intent.DatabaseID, JobID: intent.ID, Action: database.AuthorizeTransferExecute}); err != nil {
		return err
	}
	envelope, err := operations.repository.LoadResource(ctx, database.KindDatabase, intent.DatabaseID)
	if err != nil {
		return err
	}
	resource, err := database.DecodeResource(envelope)
	if err != nil {
		return err
	}
	target, ok := resource.(*database.Database)
	if !ok || target.Generation != intent.DatabaseGeneration {
		return database.ErrTransferStale
	}
	if target.Status.Lifecycle != database.LifecycleReady || target.Status.Health != database.HealthHealthy || target.Status.Reconciliation != database.ReconciliationInSync {
		return database.ErrUnavailable
	}
	return nil
}

func (operations *DatabaseTransferOperations) ExecuteDatabaseUpload(ctx context.Context, inv Invocation, request database.TransferUploadRequest) (database.TransferUploadResult, error) {
	if request.Validate() != nil {
		return database.TransferUploadResult{}, ErrInvalidRequest
	}
	if err := operations.authorizeUpload(ctx, inv, request.Intent); err != nil {
		return database.TransferUploadResult{}, err
	}
	result, err := operations.coordinator.ExecuteTransferUpload(ctx, request)
	class, outcome := audit.ClassMutation, audit.OutcomeApplied
	if request.Action == "status" {
		class, outcome = audit.ClassSensitiveRead, audit.OutcomeAllowed
	}
	if err != nil {
		outcome = audit.OutcomeFailed
	}
	if errors.Is(err, database.ErrAmbiguous) {
		outcome = audit.OutcomeAmbiguous
	}
	// Only digests/scope/offset reach audit storage, never uploaded SQL bytes.
	raw, _ := json.Marshal(request)
	digest := sha256.Sum256(raw)
	requestDigest := hex.EncodeToString(digest[:])
	intent := request.Intent
	now := time.Now().UTC()
	eventID := sha256.Sum256([]byte(requestDigest + "\x00" + inv.Request.RequestID + "\x00" + now.Format(time.RFC3339Nano)))
	_, auditErr := operations.audit.Append(ctx, audit.Event{ID: "dbupload-" + hex.EncodeToString(eventID[:]), Class: class, Action: "database.upload." + request.Action, Actor: audit.Actor{PrincipalID: inv.Actor.PrincipalID.String(), CredentialID: inv.Actor.CredentialID.String(), SessionID: inv.Actor.SessionID.String(), TenantID: intent.TenantID.String(), AuthzEpoch: inv.Actor.AuthzEpoch, Assurance: fmt.Sprint(inv.Actor.Assurance), Origin: inv.Meta.Origin}, Target: audit.Target{Kind: "database_upload", ID: intent.ID.String(), TenantID: intent.TenantID.String(), Generation: fmt.Sprint(intent.DatabaseGeneration)}, Outcome: outcome, RequestDigest: requestDigest, TraceID: inv.Request.RequestID, Attributes: map[string]string{"database_id": intent.DatabaseID.String(), "site_id": intent.SiteID.String(), "intent_digest": intent.Digest, "offset": fmt.Sprint(result.NextOffset)}, OccurredAt: now})
	if err != nil {
		return result, err
	}
	if auditErr != nil {
		return result, database.ErrAmbiguous
	}
	return result, nil
}

func bootstrapDatabaseUploadIntents(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS database_upload_intents_v1 (upload_id TEXT PRIMARY KEY, document BLOB NOT NULL) STRICT`)
	return err
}

// Persist before privileged allocation so a retry after an ambiguous response
// reuses its original timestamp, expiry and artifact identity.
func (operations *DatabaseTransferOperations) persistUploadIntent(ctx context.Context, intent database.TransferUploadIntent) (database.TransferUploadIntent, error) {
	if operations == nil || operations.control == nil || intent.Validate() != nil {
		return database.TransferUploadIntent{}, ErrInvalidRequest
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return database.TransferUploadIntent{}, err
	}
	if _, err = operations.control.ExecContext(ctx, `INSERT INTO database_upload_intents_v1(upload_id,document) VALUES(?,?) ON CONFLICT(upload_id) DO NOTHING`, intent.ID.String(), raw); err != nil {
		return database.TransferUploadIntent{}, err
	}
	if err = operations.control.QueryRowContext(ctx, `SELECT document FROM database_upload_intents_v1 WHERE upload_id=?`, intent.ID.String()).Scan(&raw); err != nil {
		return database.TransferUploadIntent{}, err
	}
	var stored database.TransferUploadIntent
	if json.Unmarshal(raw, &stored) != nil || stored.Validate() != nil {
		return database.TransferUploadIntent{}, database.ErrTransferInvalid
	}
	intent.CreatedAt, intent.ExpiresAt = stored.CreatedAt, stored.ExpiresAt
	intent, err = database.SealTransferUploadIntent(intent)
	if err != nil || intent.Digest != stored.Digest {
		return database.TransferUploadIntent{}, database.ErrConflict
	}
	return stored, nil
}
