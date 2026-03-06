// Package certificates manages TLS certificates for MetalWAF — manual uploads
// and Let's Encrypt via autocert. Private keys are encrypted at rest with
// AES-256-GCM when METALWAF_MASTER_KEY is set.
package certificates

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// EncryptKey encrypts a private key PEM with AES-256-GCM.
// If masterKey is nil or empty the plaintext is returned unchanged — useful for
// development and single-node deployments where the SQLite file is the security
// boundary.
//
// Ciphertext layout: [12-byte random nonce][ciphertext+16-byte auth tag].
func EncryptKey(plaintext, masterKey []byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(deriveKey(masterKey))
	if err != nil {
		return nil, fmt.Errorf("certificates: encrypt: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("certificates: encrypt: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("certificates: encrypt: generating nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptKey decrypts a ciphertext produced by EncryptKey.
// If masterKey is nil or empty the ciphertext is returned unchanged.
func DecryptKey(ciphertext, masterKey []byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return ciphertext, nil
	}
	block, err := aes.NewCipher(deriveKey(masterKey))
	if err != nil {
		return nil, fmt.Errorf("certificates: decrypt: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("certificates: decrypt: %w", err)
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("certificates: decrypt: ciphertext too short")
	}
	plain, err := gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("certificates: decrypt: authentication failed — wrong master key or corrupted data: %w", err)
	}
	return plain, nil
}

// deriveKey shrinks or stretches masterKey to exactly 32 bytes (AES-256) via
// a single-pass SHA-256.
func deriveKey(masterKey []byte) []byte {
	h := sha256.Sum256(masterKey)
	return h[:]
}
