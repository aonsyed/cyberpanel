package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"errors"
)

// EnrollExact closes the write-only management client's lost-response window.
// Existing active version 1 is accepted only for byte-identical material and
// the complete original authority. It cannot rotate, resurrect, or read back a
// secret. No plaintext digest is persisted as a password-guessing oracle.
func (b *Broker) EnrollExact(ctx context.Context, request PutRequest) (Metadata, error) {
	defer wipe(request.Plaintext)
	if b == nil || ctx == nil || request.ExpectedVersion != 0 || request.ExpectedBindingDigest != "" { return Metadata{}, ErrInvalid }
	first := request
	first.Plaintext = append([]byte(nil), request.Plaintext...)
	metadata, err := b.Put(ctx, first)
	if err == nil { return metadata, nil }
	if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrRollback) { return Metadata{}, err }
	b.mu.Lock()
	defer b.mu.Unlock()
	metadata, err = b.store.Head(ctx, request.ID)
	if err != nil { return Metadata{}, err }
	if metadata.State != StateActive { return Metadata{}, ErrRevoked }
	if metadata.Version != 1 || metadata.OwnerTenantID != request.OwnerTenantID || metadata.Purpose != request.Purpose || digestJSON(metadata.Audience) != digestJSON(request.Audience) { return Metadata{}, ErrConflict }
	record, err := b.store.Record(ctx, request.ID, 1)
	if err != nil { return Metadata{}, err }
	if !hmac.Equal(record.AAD, canonicalAAD(metadata)) || digest(record.WrappedDEK) != metadata.WrappedDEKDigest || digest(record.Ciphertext) != metadata.CiphertextDigest { return Metadata{}, ErrConflict }
	key, err := b.kek.Unwrap(ctx, metadata.KeyEpoch, record.WrappedDEK, record.AAD)
	if err != nil { return Metadata{}, err }
	defer wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil { return Metadata{}, err }
	aead, err := cipher.NewGCM(block)
	if err != nil || len(record.Nonce) != aead.NonceSize() { return Metadata{}, ErrConflict }
	plaintext, err := aead.Open(nil, record.Nonce, record.Ciphertext, record.AAD)
	defer wipe(plaintext)
	if err != nil || !hmac.Equal(plaintext, request.Plaintext) { return Metadata{}, ErrConflict }
	return metadata, nil
}
