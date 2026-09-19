package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// PasswordBinding identifies one consumer of a broker-generated password.
// Pair provisioning is create-only and returns metadata, never material.
type PasswordBinding struct {
	ID            ID              `json:"id"`
	OwnerTenantID ID              `json:"owner_tenant_id"`
	Audience      AudienceBinding `json:"audience"`
}

func validatePasswordPair(request ManagementRequest) error {
	if request.Purpose != PurposeDatabase || request.ExpectedVersion != 0 || request.ExpectedBindingDigest != "" || len(request.Material) != 0 || request.PasswordReplica == nil {
		return ErrInvalid
	}
	replica := request.PasswordReplica
	if !replica.ID.Valid() || !replica.OwnerTenantID.Valid() || replica.ID == request.SecretID || replica.Audience.Validate() != nil || replica.Audience.ConsumerReleaseDigest != request.Audience.ConsumerReleaseDigest {
		return ErrInvalid
	}
	for _, audience := range []AudienceBinding{request.Audience, replica.Audience} {
		if len(audience.Operations) != 1 || audience.Operations[0] != OperationAuthenticate {
			return ErrInvalid
		}
	}
	return nil
}

func passwordPairMetadataMatches(head Metadata, request ManagementRequest, binding PasswordBinding) bool {
	return head.Validate() == nil && head.ID == binding.ID && head.OwnerTenantID == binding.OwnerTenantID && head.Purpose == PurposeDatabase && head.Version == 1 && head.State == StateActive && digestJSON(head.Audience) == digestJSON(binding.Audience)
}

func validatePasswordPairResponse(request ManagementRequest, response ManagementResponse) error {
	if validatePasswordPair(request) != nil || len(response.PublicKey) != 0 || response.ReplicaMetadata == nil ||
		!passwordPairMetadataMatches(response.Metadata, request, PasswordBinding{ID: request.SecretID, OwnerTenantID: request.OwnerTenantID, Audience: request.Audience}) ||
		!passwordPairMetadataMatches(*response.ReplicaMetadata, request, *request.PasswordReplica) {
		return ErrInvalid
	}
	return nil
}

func (client *ManagementClient) ProvisionPasswordPair(ctx context.Context, primary, replica PasswordBinding) (Metadata, Metadata, error) {
	if client == nil || client.transport == nil || ctx == nil {
		return Metadata{}, Metadata{}, ErrInvalid
	}
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		return Metadata{}, Metadata{}, err
	}
	now := client.now().UTC()
	deadline := now.Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	request := ManagementRequest{Version: ManagementProtocolVersion, RequestID: "mgt-" + hex.EncodeToString(identifier), Action: ManagementProvisionPasswordPair, SecretID: primary.ID, OwnerTenantID: primary.OwnerTenantID, Purpose: PurposeDatabase, Audience: primary.Audience, PasswordReplica: &replica, Deadline: deadline}
	if err := request.Validate(now); err != nil {
		return Metadata{}, Metadata{}, err
	}
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil {
		return Metadata{}, Metadata{}, err
	}
	if err := response.Validate(request); err != nil {
		return Metadata{}, Metadata{}, err
	}
	if response.FailureCode != "" {
		return Metadata{}, Metadata{}, materialFailure(response.FailureCode)
	}
	return response.Metadata, *response.ReplicaMetadata, nil
}

// Both envelopes and their immutable pairing are committed in one SQLite
// transaction. A lost response is replayed by complete authority, not request ID.
// Pre-existing independently enrolled secrets are never adopted as a pair.
func (broker *Broker) provisionPasswordPair(ctx context.Context, request ManagementRequest) (Metadata, Metadata, error) {
	if broker == nil || ctx == nil || request.Validate(broker.clock().UTC()) != nil || request.Action != ManagementProvisionPasswordPair {
		return Metadata{}, Metadata{}, ErrInvalid
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	tx, err := broker.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Metadata{}, Metadata{}, err
	}
	defer tx.Rollback()
	var storedDigest string
	// Pair intent contains no password or password-derived value.
	intent := struct{ Primary, Replica PasswordBinding }{PasswordBinding{ID: request.SecretID, OwnerTenantID: request.OwnerTenantID, Audience: request.Audience}, *request.PasswordReplica}
	intentDigest := digestJSON(intent)
	err = tx.QueryRowContext(ctx, `SELECT intent_digest FROM secret_password_pairs WHERE primary_id=?`, request.SecretID).Scan(&storedDigest)
	if err == nil {
		if storedDigest != intentDigest {
			return Metadata{}, Metadata{}, ErrConflict
		}
		var heads [2]Metadata
		for index, binding := range []PasswordBinding{intent.Primary, intent.Replica} {
			var version uint64
			if err := tx.QueryRowContext(ctx, `SELECT current_version FROM secret_heads WHERE secret_id=?`, binding.ID).Scan(&version); err != nil {
				return Metadata{}, Metadata{}, err
			}
			record, err := loadRecordTx(ctx, tx, binding.ID, version)
			if err != nil {
				return Metadata{}, Metadata{}, err
			}
			if !passwordPairMetadataMatches(record.Metadata, request, binding) || digest(record.Ciphertext) != record.Metadata.CiphertextDigest || digest(record.WrappedDEK) != record.Metadata.WrappedDEKDigest || string(record.AAD) != string(canonicalAAD(record.Metadata)) {
				return Metadata{}, Metadata{}, ErrConflict
			}
			heads[index] = record.Metadata
		}
		return heads[0], heads[1], tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Metadata{}, Metadata{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_heads WHERE secret_id IN (?,?)`, intent.Primary.ID, intent.Replica.ID).Scan(&count); err != nil {
		return Metadata{}, Metadata{}, err
	}
	if count != 0 {
		return Metadata{}, Metadata{}, ErrConflict
	}
	random := make([]byte, 32)
	defer wipe(random)
	if _, err := rand.Read(random); err != nil {
		return Metadata{}, Metadata{}, err
	}
	password := make([]byte, base64.RawURLEncoding.EncodedLen(len(random)))
	base64.RawURLEncoding.Encode(password, random)
	defer wipe(password)
	var heads [2]Metadata
	for index, binding := range []PasswordBinding{intent.Primary, intent.Replica} {
		record, err := broker.passwordPairRecord(ctx, binding.OwnerTenantID, binding, password)
		if err != nil {
			return Metadata{}, Metadata{}, err
		}
		metadata := record.Metadata
		raw, err := json.Marshal(metadata)
		if err != nil {
			return Metadata{}, Metadata{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO secret_records VALUES(?,?,?,?,?,?,?,?,?,?,?)`, metadata.ID, metadata.Version, metadata.OwnerTenantID, metadata.State, metadata.KeyEpoch, raw, record.Nonce, record.WrappedDEK, record.Ciphertext, record.AAD, metadata.CreatedAt); err != nil {
			return Metadata{}, Metadata{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO secret_heads VALUES(?,?,?,?,?,?,?)`, metadata.ID, metadata.OwnerTenantID, metadata.Version, metadata.KeyEpoch, metadata.State, metadata.BindingDigest, metadata.CreatedAt); err != nil {
			return Metadata{}, Metadata{}, err
		}
		heads[index] = metadata
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO secret_password_pairs(primary_id,replica_id,intent_digest) VALUES(?,?,?)`, intent.Primary.ID, intent.Replica.ID, intentDigest); err != nil {
		return Metadata{}, Metadata{}, err
	}
	return heads[0], heads[1], tx.Commit()
}

func (broker *Broker) passwordPairRecord(ctx context.Context, owner ID, binding PasswordBinding, password []byte) (SecretRecord, error) {
	epoch, err := broker.kek.Epoch(ctx)
	if err != nil {
		return SecretRecord{}, err
	}
	key := make([]byte, 32)
	defer wipe(key)
	if _, err := rand.Read(key); err != nil {
		return SecretRecord{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return SecretRecord{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return SecretRecord{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return SecretRecord{}, err
	}
	metadata := Metadata{ID: binding.ID, OwnerTenantID: owner, Purpose: PurposeDatabase, Version: 1, KeyEpoch: epoch, State: StateActive, Audience: binding.Audience, Algorithm: "AES-256-GCM", CreatedAt: broker.clock().UTC()}
	metadata.BindingDigest = digestJSON(bindingDTO(metadata))
	aad := canonicalAAD(metadata)
	ciphertext := aead.Seal(nil, nonce, password, aad)
	wrapped, err := broker.kek.Wrap(ctx, epoch, key, aad)
	if err != nil {
		return SecretRecord{}, err
	}
	metadata.CiphertextDigest, metadata.WrappedDEKDigest = digest(ciphertext), digest(wrapped)
	if err := metadata.Validate(); err != nil {
		return SecretRecord{}, err
	}
	return SecretRecord{Metadata: metadata, Nonce: nonce, WrappedDEK: wrapped, Ciphertext: ciphertext, AAD: aad}, nil
}
