//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

type secretEnrollmentClient struct{ client *secrets.ManagementClient }

func newSecretEnrollmentClient() (*secretEnrollmentClient, error) {
	client, err := secrets.NewLocalManagementClient()
	if err != nil {
		return nil, err
	}
	return &secretEnrollmentClient{client: client}, nil
}

func (client *secretEnrollmentClient) Enroll(ctx context.Context, request apiserver.SecretEnrollmentRequest) (apiserver.SecretReference, error) {
	if err := validateSecretEnrollmentCall(request.Call, request.OwnerID, request.Audience.ResourceID); err != nil {
		wipeBytes(request.Material)
		return apiserver.SecretReference{}, err
	}
	metadata, err := client.client.Put(ctx, secrets.PutRequest{
		ID:              request.SecretID,
		OwnerTenantID:   request.OwnerID,
		Purpose:         request.Purpose,
		Audience:        request.Audience,
		Plaintext:       request.Material,
		ExpectedVersion: 0,
	})
	if err != nil {
		return apiserver.SecretReference{}, err
	}
	return secretReference(metadata), nil
}

func (client *secretEnrollmentClient) Rotate(ctx context.Context, request apiserver.SecretRotationRequest) (apiserver.SecretReference, error) {
	if request.ExpectedVersion == 0 {
		wipeBytes(request.Material)
		return apiserver.SecretReference{}, secrets.ErrInvalid
	}
	if err := validateSecretEnrollmentCall(request.Call, request.OwnerID, request.Audience.ResourceID); err != nil {
		wipeBytes(request.Material)
		return apiserver.SecretReference{}, err
	}
	metadata, err := client.client.Put(ctx, secrets.PutRequest{
		ID:              request.SecretID,
		OwnerTenantID:   request.OwnerID,
		Purpose:         request.Purpose,
		Audience:        request.Audience,
		Plaintext:       request.Material,
		ExpectedVersion: request.ExpectedVersion,
		ExpectedBindingDigest: request.ExpectedBindingDigest,
	})
	if err != nil {
		return apiserver.SecretReference{}, err
	}
	return secretReference(metadata), nil
}

func validateSecretEnrollmentCall(call apiserver.EdgeCall, owner, resource secrets.ID) error {
	if call.CommandID == "" || call.PrincipalID == "" || call.Assurance < identity.AssuranceMFA || scopedSecretID("resource", call.ResourceID) != resource {
		return secrets.ErrForbidden
	}
	if call.TenantID == "" {
		if owner.String() != "installation" {
			return secrets.ErrForbidden
		}
	} else if owner != scopedSecretID("tenant", call.TenantID) {
		return secrets.ErrForbidden
	}
	return nil
}

func scopedSecretID(namespace, value string) secrets.ID {
	if id, err := secrets.NewID(value); err == nil {
		return id
	}
	digest := sha256.Sum256([]byte(namespace + "\x00" + value))
	return secrets.ID(namespace + "_" + hex.EncodeToString(digest[:])[:48])
}

func secretReference(metadata secrets.Metadata) apiserver.SecretReference {
	return apiserver.SecretReference{
		ID:            metadata.ID,
		Purpose:       metadata.Purpose,
		ResourceKind:  metadata.Audience.ResourceKind,
		ResourceID:    metadata.Audience.ResourceID,
		Version:       metadata.Version,
		BindingDigest: metadata.BindingDigest,
		State:         metadata.State,
		CreatedAt:     metadata.CreatedAt,
	}
}

var _ apiserver.SecretEnrollmentService = (*secretEnrollmentClient)(nil)
var _ = errors.Is
