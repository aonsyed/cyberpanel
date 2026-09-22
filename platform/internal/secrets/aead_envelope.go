package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// SealAEADEnvelope uses the broker's AES-256-GCM nonce/ciphertext contract.
// Whole-object callers must honor the same bounded plaintext limit; this is
// deliberately not a new streaming cryptographic framing protocol.
func SealAEADEnvelope(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != 32 || len(plaintext) > MaterialMaximumBytes || len(aad) == 0 {
		return nil, nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func OpenAEADEnvelope(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 || len(aad) == 0 {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() || len(ciphertext) < aead.Overhead() || len(ciphertext) > MaterialMaximumBytes+aead.Overhead() {
		return nil, ErrInvalid
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
