//go:build linux

package accesspolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// EnrolledCredential is the secret broker plaintext schema. PasswordBase64 is
// decoded by encoding/json directly into wipeable bytes, avoiding a durable or
// API-visible plaintext password string.
type EnrolledCredential struct {
	Username       string `json:"username"`
	PasswordBase64 []byte `json:"password_base64"`
}

type LocalCredentialSource struct{ client *secrets.MaterialClient }

func NewLocalCredentialSource() (*LocalCredentialSource, error) {
	client, err := secrets.NewLocalMaterialClient()
	if err != nil { return nil, err }
	return &LocalCredentialSource{client: client}, nil
}

func (source *LocalCredentialSource) Resolve(ctx context.Context, credentialRef, tenantID, resourceID string) (CredentialMaterial, error) {
	if source == nil || source.client == nil || credentialRef == "" || tenantID == "" || resourceID == "" {
		return CredentialMaterial{}, ErrInvalid
	}
	secretID, err := secrets.NewID(credentialRef)
	if err != nil { return CredentialMaterial{}, ErrInvalid }
	response, err := source.client.Read(ctx, secrets.MaterialRequest{SecretID: secretID, OwnerTenantID: scopedSecretID("tenant", tenantID), Purpose: secrets.PurposeAuthentication, Operation: secrets.OperationAuthenticate, AdapterID: SecretAdapterID, AdapterVersion: SecretAdapterVersion, ResourceID: scopedSecretID("resource", resourceID)})
	if err != nil { return CredentialMaterial{}, err }
	defer wipe(response.Material)
	if len(response.Material) == 0 || len(response.Material) > MaximumMaterialBytes {
		return CredentialMaterial{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Material))
	decoder.DisallowUnknownFields()
	var enrolled EnrolledCredential
	if err = decoder.Decode(&enrolled); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		wipe(enrolled.PasswordBase64)
		return CredentialMaterial{}, ErrInvalid
	}
	material, err := newCredentialMaterial(enrolled.Username, enrolled.PasswordBase64)
	wipe(enrolled.PasswordBase64)
	return material, err
}

func scopedSecretID(namespace, value string) secrets.ID {
	if id, err := secrets.NewID(value); err == nil { return id }
	digest := sha256.Sum256([]byte(namespace + "\x00" + value))
	id, err := secrets.NewID(namespace + "_" + hex.EncodeToString(digest[:])[:48])
	if err != nil { panic(errors.New("invalid deterministic secret scope")) }
	return id
}

var _ CredentialSource = (*LocalCredentialSource)(nil)
