package database

import (
	"encoding/json"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

const MaximumTransferUploadBytes uint64 = 64 << 20
const MaximumTransferUploadChunk = 256 << 10

// TransferUploadIntent binds uploaded bytes to an authorized destination.
// Its digest is an integrity binding, not authorization: the API must authorize
// every request before passing it over the authenticated executor boundary.
type TransferUploadIntent struct {
	ID                 ResourceID          `json:"id"`
	TenantID           site.TenantID       `json:"tenant_id"`
	SiteID             site.SiteID         `json:"site_id"`
	DatabaseID         ResourceID          `json:"database_id"`
	DatabaseGeneration uint64              `json:"database_generation"`
	CreatedBy          string              `json:"created_by"`
	Compression        TransferCompression `json:"compression"`
	Bytes              uint64              `json:"bytes"`
	PayloadDigest      string              `json:"payload_digest"`
	CreatedAt          time.Time           `json:"created_at"`
	ExpiresAt          time.Time           `json:"expires_at"`
	Digest             string              `json:"digest"`
}

func SealTransferUploadIntent(intent TransferUploadIntent) (TransferUploadIntent, error) {
	intent.Digest = transferUploadDigest(intent)
	return intent, intent.Validate()
}

func transferUploadDigest(intent TransferUploadIntent) string {
	intent.Digest = ""
	raw, _ := json.Marshal(intent)
	return transferDigest(raw)
}

func (intent TransferUploadIntent) Validate() error {
	if intent.ID.IsZero() || intent.TenantID.String() == "" || intent.SiteID.String() == "" || intent.DatabaseID.IsZero() || intent.DatabaseGeneration == 0 || !validTransferIdentifier(intent.CreatedBy) || !validTransferCompression(intent.Compression) || intent.Bytes == 0 || intent.Bytes > MaximumTransferUploadBytes || !validSHA256(intent.PayloadDigest) || intent.CreatedAt.IsZero() || !intent.ExpiresAt.After(intent.CreatedAt) || intent.ExpiresAt.Sub(intent.CreatedAt) > 24*time.Hour || !validSHA256(intent.Digest) || intent.Digest != transferUploadDigest(intent) {
		return ErrTransferInvalid
	}
	return nil
}

func (intent TransferUploadIntent) ArtifactIdentity() TransferArtifactIdentity {
	store, _ := NewResourceID("upload-" + intent.Digest)
	return TransferArtifactIdentity{StoreID: store, ArtifactID: intent.ID, Generation: 1}
}

func (intent TransferUploadIntent) matchesArtifact(artifact TransferArtifactDescriptor) bool {
	return intent.Validate() == nil && artifact.Validate() == nil && artifact.Identity == intent.ArtifactIdentity() && artifact.Format == TransferFormatSQL && artifact.Compression == intent.Compression && artifact.Bytes == intent.Bytes && artifact.Digest == intent.PayloadDigest && artifact.Rows == 0 && artifact.ExpiresAt.Equal(intent.ExpiresAt)
}

func validTransferUploadSource(job TransferJob) bool {
	intent := job.UploadSource
	return intent != nil && job.Source != nil && intent.matchesArtifact(*job.Source) && intent.TenantID == job.TenantID && intent.SiteID == job.SiteID && intent.DatabaseID == job.DatabaseID && intent.DatabaseGeneration == job.DatabaseGeneration && intent.CreatedBy == job.CreatedBy && !job.CreatedAt.Before(intent.CreatedAt) && job.CreatedAt.Before(intent.ExpiresAt)
}
