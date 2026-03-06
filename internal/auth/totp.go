package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 4226) mandates HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpPeriod = 30 // seconds (RFC 6238 default)
	totpDigits = 6
	totpWindow = 1 // ±1 period tolerance for clock skew
)

// GenerateTOTPSecret creates a random 160-bit (20-byte) TOTP shared secret
// and returns it as a base32-encoded string (no padding), as expected by
// RFC 4226 / RFC 6238 authenticator apps.
func GenerateTOTPSecret() (string, error) {
	key := make([]byte, 20)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("totp: generating random secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key), nil
}

// TOTPUri builds the otpauth:// URI used by authenticator apps (Google
// Authenticator, Authy, etc.) to import the TOTP secret.
// The frontend can render this URI as a QR code.
func TOTPUri(secret, issuer, username string) string {
	label := url.PathEscape(issuer + ":" + username)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// ValidateTOTP returns true if code (6-digit string) matches the TOTP value
// derived from secret at the current time. A ±1 period window is allowed.
func ValidateTOTP(code, secret string) bool {
	if len(code) != totpDigits {
		return false
	}
	// Normalise secret: strip whitespace, equalise padding, uppercase.
	secret = strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(secret)), " ", "")
	// base32 without padding is stored in the DB.
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// Try with standard padding as fallback.
		padded := secret
		for len(padded)%8 != 0 {
			padded += "="
		}
		key, err = base32.StdEncoding.DecodeString(padded)
		if err != nil {
			return false
		}
	}
	counter := time.Now().Unix() / totpPeriod
	for i := -totpWindow; i <= totpWindow; i++ {
		if hotpCode(key, uint64(counter+int64(i))) == code {
			return true
		}
	}
	return false
}

// hotpCode computes an HOTP value as per RFC 4226 §5.4.
func hotpCode(key []byte, counter uint64) string {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, key) //nolint:gosec // required by RFC 4226
	mac.Write(msg)
	h := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3).
	offset := h[19] & 0x0F
	code := (int(h[offset])&0x7F)<<24 |
		int(h[offset+1])<<16 |
		int(h[offset+2])<<8 |
		int(h[offset+3])

	return fmt.Sprintf("%06d", code%1_000_000)
}
