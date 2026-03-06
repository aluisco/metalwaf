package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/hkdf"
)

const cacheFileName = ".license_cache"

// cacheEntry is the structure persisted to disk (AES-GCM encrypted).
// It stores the JWT returned by the license server and when it was last
// successfully obtained online.
type cacheEntry struct {
	Token       string    `json:"token"`        // JWT issued and signed by the license server
	LastChecked time.Time `json:"last_checked"` // time of last successful online validation
	Fingerprint string    `json:"fingerprint"`  // fingerprint at the time the token was obtained
}

// deriveKey produces a 32-byte AES key unique to this (licenseKey, fingerprint)
// pair using HKDF-SHA256. This ensures the cache file is unreadable on any
// other machine or with any other license key.
func deriveKey(licenseKey, fingerprint string) ([]byte, error) {
	r := hkdf.New(sha256.New, []byte(licenseKey), []byte(fingerprint), []byte("metalwaf-license-cache-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("deriving cache encryption key: %w", err)
	}
	return key, nil
}

// writeCache encrypts the entry and persists it to cacheDir/.license_cache.
// The file is written with mode 0600 (owner read/write only).
func writeCache(cacheDir, licenseKey, fingerprint string, entry cacheEntry) error {
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	plaintext, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling cache entry: %w", err)
	}

	key, err := deriveKey(licenseKey, fingerprint)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	// Format: nonce || ciphertext+tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	path := filepath.Join(cacheDir, cacheFileName)
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("writing cache file: %w", err)
	}
	return nil
}

// readCache decrypts and returns the cached entry.
// Returns (nil, nil) if the file does not exist or cannot be decrypted
// (corruption or wrong key) — both are treated as a cache miss.
func readCache(cacheDir, licenseKey, fingerprint string) (*cacheEntry, error) {
	path := filepath.Join(cacheDir, cacheFileName)
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // clean cache miss
		}
		return nil, fmt.Errorf("reading cache file: %w", err)
	}

	key, err := deriveKey(licenseKey, fingerprint)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("cache file is too short to be valid")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Corrupted or encrypted with a different key — treat as cache miss.
		return nil, nil
	}

	var entry cacheEntry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return nil, nil // malformed JSON — treat as cache miss
	}
	return &entry, nil
}
