//go:build linux

package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

type ApplicationSecretLease struct {
	InstallationID InstallationID `json:"installation_id"`
	Purpose        string         `json:"purpose"`
	Metadata       secrets.Metadata `json:"metadata"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

func (lease ApplicationSecretLease) Validate() error {
	if !validID(string(lease.InstallationID)) || !validID(lease.Purpose) || lease.Metadata.Validate()!=nil || lease.UpdatedAt.IsZero() { return ErrInvalid }
	return nil
}

func (repository SQLRepository) LoadApplicationSecretLease(ctx context.Context, id secrets.ID) (ApplicationSecretLease,error) {
	if repository.DB==nil || ctx==nil || !id.Valid() { return ApplicationSecretLease{},ErrInvalid }
	var payload []byte
	err:=repository.DB.QueryRowContext(ctx,`SELECT metadata_json FROM app_secret_leases WHERE secret_id=?`,id).Scan(&payload)
	if errors.Is(err,sql.ErrNoRows) { return ApplicationSecretLease{},ErrNotFound }
	if err!=nil { return ApplicationSecretLease{},err }
	var lease ApplicationSecretLease
	if json.Unmarshal(payload,&lease)!=nil || lease.Validate()!=nil || lease.Metadata.ID!=id { return ApplicationSecretLease{},ErrIntegrity }
	return lease,nil
}

func (repository SQLRepository) SaveApplicationSecretLease(ctx context.Context, lease ApplicationSecretLease) error {
	if repository.DB==nil || ctx==nil || lease.Validate()!=nil { return ErrInvalid }
	payload,err:=json.Marshal(lease);if err!=nil{return err}
	result,err:=repository.DB.ExecContext(ctx,`INSERT INTO app_secret_leases(secret_id,installation_id,purpose,version,state,metadata_json,updated_at) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(secret_id) DO UPDATE SET installation_id=excluded.installation_id,purpose=excluded.purpose,version=excluded.version,state=excluded.state,metadata_json=excluded.metadata_json,updated_at=excluded.updated_at
WHERE app_secret_leases.installation_id=excluded.installation_id AND app_secret_leases.purpose=excluded.purpose AND (app_secret_leases.version<excluded.version OR app_secret_leases.version=excluded.version)`,lease.Metadata.ID,lease.InstallationID,lease.Purpose,lease.Metadata.Version,lease.Metadata.State,payload,lease.UpdatedAt.UTC())
	if err!=nil{return err};affected,err:=result.RowsAffected();if err!=nil{return err};if affected!=1{return ErrConflict};return nil
}
