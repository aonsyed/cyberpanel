package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// RebindConsumer is a root-only management operation for an explicitly
// authorized release transition. It never returns or accepts credential material.
// The caller must authorize the destination executable before making this call.
// A rollback is another forward version bound to the previous executable, not
// a rollback of the secret's version or a reset of the external password.
func (client *ManagementClient) RebindConsumer(ctx context.Context, current Metadata, executableDigest string) (Metadata, error) {
	if client == nil || client.transport == nil || ctx == nil || current.Validate() != nil || current.State != StateActive || !validConsumerDigest(executableDigest) {
		return Metadata{}, ErrInvalid
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Metadata{}, err
	}
	now := client.now().UTC()
	deadline := now.Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value.UTC()
	}
	audience := current.Audience
	audience.ConsumerReleaseDigest = executableDigest
	request := ManagementRequest{Version: ManagementProtocolVersion, RequestID: "mgt-" + hex.EncodeToString(id), Action: ManagementRebindConsumer, SecretID: current.ID, OwnerTenantID: current.OwnerTenantID, Purpose: current.Purpose, Audience: audience, ExpectedVersion: current.Version, ExpectedBindingDigest: current.BindingDigest, Deadline: deadline}
	if err := request.Validate(now); err != nil {
		return Metadata{}, err
	}
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil {
		return Metadata{}, err
	}
	if err := response.Validate(request); err != nil {
		return Metadata{}, err
	}
	if response.FailureCode != "" {
		return Metadata{}, materialFailure(response.FailureCode)
	}
	return response.Metadata, nil
}

func validConsumerDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

func (broker *Broker) rebindConsumer(ctx context.Context, request ManagementRequest) (Metadata, error) {
	if broker == nil || ctx == nil || request.Action != ManagementRebindConsumer || request.Validate(broker.clock().UTC()) != nil {
		return Metadata{}, ErrInvalid
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	previous, err := broker.store.Record(ctx, request.SecretID, request.ExpectedVersion)
	if err != nil {
		return Metadata{}, err
	}
	old := previous.Metadata
	want := old.Audience
	want.ConsumerReleaseDigest = request.Audience.ConsumerReleaseDigest
	if old.State != StateActive || old.OwnerTenantID != request.OwnerTenantID || old.Purpose != request.Purpose || old.BindingDigest != request.ExpectedBindingDigest || old.BindingDigest != digestJSON(bindingDTO(old)) || old.Audience.ConsumerReleaseDigest == want.ConsumerReleaseDigest || digestJSON(want) != digestJSON(request.Audience) {
		return Metadata{}, ErrConflict
	}
	head, err := broker.store.Head(ctx, request.SecretID)
	if err != nil {
		return Metadata{}, err
	}
	if head.State != StateActive {
		return Metadata{}, ErrRevoked
	}
	// Lost-response replay is bounded to this exact source version and target
	// audience. Later rotations and unrelated transitions are never overwritten.
	if head.Version == old.Version+1 && head.OwnerTenantID == old.OwnerTenantID && head.Purpose == old.Purpose && digestJSON(head.Audience) == digestJSON(want) {
		return head, nil
	}
	if head.Version != old.Version || head.BindingDigest != old.BindingDigest {
		return Metadata{}, ErrConflict
	}
	if !hmac.Equal(previous.AAD, canonicalAAD(old)) || digest(previous.WrappedDEK) != old.WrappedDEKDigest || digest(previous.Ciphertext) != old.CiphertextDigest {
		return Metadata{}, ErrConflict
	}
	key, err := broker.kek.Unwrap(ctx, old.KeyEpoch, previous.WrappedDEK, previous.AAD)
	defer wipe(key)
	if err != nil {
		return Metadata{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Metadata{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(previous.Nonce) != aead.NonceSize() {
		return Metadata{}, ErrConflict
	}
	material, err := aead.Open(nil, previous.Nonce, previous.Ciphertext, previous.AAD)
	defer wipe(material)
	if err != nil || len(material) == 0 {
		return Metadata{}, ErrConflict
	}
	return broker.storeManagedMaterial(ctx, request, old.Version, material)
}
