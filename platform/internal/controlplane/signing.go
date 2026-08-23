package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"sync"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

type Ed25519IntentSigner struct {
	mu                  sync.RWMutex
	intentKeyID         string
	revocationKeyID     string
	privateKeys         map[string]ed25519.PrivateKey
}

func NewEd25519IntentSigner(intentKeyID, revocationKeyID string, privateKeys map[string]ed25519.PrivateKey) (*Ed25519IntentSigner, error) {
	if intentKeyID == "" || revocationKeyID == "" || len(privateKeys) == 0 {
		return nil, ErrInvalid
	}
	keys := make(map[string]ed25519.PrivateKey, len(privateKeys))
	for keyID, privateKey := range privateKeys {
		if keyID == "" || len(privateKey) != ed25519.PrivateKeySize {
			return nil, ErrInvalid
		}
		keys[keyID] = append(ed25519.PrivateKey(nil), privateKey...)
	}
	if len(keys[intentKeyID]) != ed25519.PrivateKeySize || len(keys[revocationKeyID]) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	return &Ed25519IntentSigner{intentKeyID: intentKeyID, revocationKeyID: revocationKeyID, privateKeys: keys}, nil
}

func (signer *Ed25519IntentSigner) IntentKeyID(ctx context.Context) (string, error) {
	if signer == nil || ctx == nil { return "", ErrInvalid }
	select { case <-ctx.Done(): return "", ctx.Err(); default: }
	signer.mu.RLock(); defer signer.mu.RUnlock()
	return signer.intentKeyID, nil
}

func (signer *Ed25519IntentSigner) RevocationKeyID(ctx context.Context) (string, error) {
	if signer == nil || ctx == nil { return "", ErrInvalid }
	select { case <-ctx.Done(): return "", ctx.Err(); default: }
	signer.mu.RLock(); defer signer.mu.RUnlock()
	return signer.revocationKeyID, nil
}

func (signer *Ed25519IntentSigner) SignIntent(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	return signer.sign(ctx, keyID, message, signer.intentKeyID)
}

func (signer *Ed25519IntentSigner) SignRevocation(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	return signer.sign(ctx, keyID, message, signer.revocationKeyID)
}

func (signer *Ed25519IntentSigner) sign(ctx context.Context, keyID string, message []byte, expected string) ([]byte, error) {
	if signer == nil || ctx == nil || len(message) == 0 || subtle.ConstantTimeCompare([]byte(keyID), []byte(expected)) != 1 {
		return nil, ErrInvalid
	}
	select { case <-ctx.Done(): return nil, ctx.Err(); default: }
	signer.mu.RLock(); key := append(ed25519.PrivateKey(nil), signer.privateKeys[keyID]...); signer.mu.RUnlock()
	if len(key) != ed25519.PrivateKeySize { return nil, ErrForbidden }
	return ed25519.Sign(key, message), nil
}

type NodeReceiptKeyProvider interface {
	NodeReceiptPublicKey(context.Context, federation.ID, string) (ed25519.PublicKey, error)
}

type Ed25519ReceiptVerifier struct{ keys NodeReceiptKeyProvider }

func NewEd25519ReceiptVerifier(keys NodeReceiptKeyProvider) (*Ed25519ReceiptVerifier, error) {
	if keys == nil { return nil, ErrInvalid }
	return &Ed25519ReceiptVerifier{keys: keys}, nil
}

func (verifier *Ed25519ReceiptVerifier) VerifyNodeReceipt(ctx context.Context, nodeID federation.ID, keyID string, message, signature []byte) error {
	if verifier == nil || verifier.keys == nil || ctx == nil || !nodeID.Valid() || keyID == "" || len(message) == 0 || len(signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	key, err := verifier.keys.NodeReceiptPublicKey(ctx, nodeID, keyID)
	if err != nil { return err }
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, signature) {
		return errors.Join(ErrForbidden, errors.New("node receipt signature rejected"))
	}
	return nil
}
