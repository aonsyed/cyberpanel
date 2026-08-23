package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
)

type Ed25519ReceiptSigner struct {
	keyID      string
	privateKey ed25519.PrivateKey
}

func NewEd25519ReceiptSigner(keyID string, privateKey ed25519.PrivateKey) (*Ed25519ReceiptSigner, error) {
	if keyID == "" || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	return &Ed25519ReceiptSigner{keyID: keyID, privateKey: append(ed25519.PrivateKey(nil), privateKey...)}, nil
}

func (signer *Ed25519ReceiptSigner) ReceiptKeyID(ctx context.Context) (string, error) {
	if signer == nil || ctx == nil { return "", ErrInvalid }
	select { case <-ctx.Done(): return "", ctx.Err(); default: }
	return signer.keyID, nil
}

func (signer *Ed25519ReceiptSigner) SignReceipt(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	if signer == nil || ctx == nil || len(message) == 0 || subtle.ConstantTimeCompare([]byte(keyID), []byte(signer.keyID)) != 1 {
		return nil, ErrInvalid
	}
	select { case <-ctx.Done(): return nil, ctx.Err(); default: }
	return ed25519.Sign(signer.privateKey, message), nil
}
