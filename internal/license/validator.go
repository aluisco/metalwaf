package license

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// serverPublicKeyHex is the Ed25519 public key (64-char hex, 32 bytes) used to
// verify JWT tokens issued by the MetalWAF license server.
//
// Set at build time for release builds via:
//
//	go build -ldflags "-X github.com/metalwaf/metalwaf/internal/license.serverPublicKeyHex=<hex>"
//
// When empty (local / source builds), the JWT signature is NOT verified and a
// prominent development-mode warning is logged. Official binaries from
// metalwaf.io always have this value set.
var serverPublicKeyHex string

// validateRequest is the body sent to POST /v1/validate.
type validateRequest struct {
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
	Version     string `json:"version"`
}

// validateResponse is the body returned by the license server.
type validateResponse struct {
	Valid bool   `json:"valid"`
	Token string `json:"token"` // Ed25519-signed JWT containing license claims
	Error string `json:"error,omitempty"`
}

// licenseClaims are the custom JWT claims embedded in server tokens.
type licenseClaims struct {
	jwt.RegisteredClaims
	LicenseID    string `json:"lid"`
	CustomerName string `json:"cname"`
	Tier         string `json:"tier"`
	MaxSites     int    `json:"max_sites"`
	Fingerprint  string `json:"fp"`
}

// Validate checks the provided licenseKey against the MetalWAF license server
// and returns the active License object. The caller must never make licensing
// decisions based on any other source of truth.
//
// Behavior summary:
//   - Empty licenseKey → LITE edition, no server call made.
//   - Online validation succeeds → PRO license, cache refreshed.
//   - Online fails, valid cache exists, grace period not expired → PRO (offline).
//   - Online fails, no valid cache or grace period expired → LITE with error log.
//
// cacheDir is where the encrypted cache file is stored (typically the data dir).
// appVersion is sent to the server for compatibility telemetry.
func Validate(ctx context.Context, licenseKey, cacheDir, appVersion string) *License {
	licenseKey = strings.TrimSpace(licenseKey)
	if licenseKey == "" {
		slog.Info("license: no key provided, running as LITE (free edition)")
		return liteOnly()
	}

	slog.Info("license: validating key", "key", maskKey(licenseKey))

	fingerprint := machineFingerprint()
	serverURL := os.Getenv("METALWAF_LICENSE_SERVER")
	if serverURL == "" {
		serverURL = defaultLicenseServer
	}

	// ── 1. Try online validation ────────────────────────────────────────────
	lic, token, err := validateOnline(ctx, serverURL, licenseKey, fingerprint, appVersion)
	if err == nil {
		slog.Info("license: online validation successful",
			"edition", lic.Edition(),
			"customer", lic.CustomerName,
			"offline_mode", false,
		)
		entry := cacheEntry{
			Token:       token,
			LastChecked: time.Now().UTC(),
			Fingerprint: fingerprint,
		}
		if werr := writeCache(cacheDir, licenseKey, fingerprint, entry); werr != nil {
			slog.Warn("license: could not write local cache", "error", werr)
		}
		lic.Offline = false
		return lic
	}
	slog.Warn("license: online validation failed, trying local cache", "error", err)

	// ── 2. Fall back to local encrypted cache ───────────────────────────────
	entry, cerr := readCache(cacheDir, licenseKey, fingerprint)
	if cerr != nil {
		slog.Warn("license: could not read local cache", "error", cerr)
	}

	if entry != nil {
		lic, verr := verifyToken(entry.Token)
		if verr == nil {
			lic.LastChecked = entry.LastChecked
			lic.Offline = true

			if lic.GracePeriodExpired() {
				slog.Error("license: offline grace period has expired — reverting to LITE edition",
					"last_online_check", entry.LastChecked.Format(time.RFC3339),
					"grace_period", gracePeriod.String(),
					"action_required", "restore network connectivity to the license server",
				)
				return liteOnly()
			}

			days := lic.DaysUntilGraceExpiry()
			if days <= 2 {
				slog.Warn("license: running offline — grace period ending very soon",
					"days_remaining", days,
					"action_required", "restore network connectivity to restore online validation",
				)
			} else {
				slog.Info("license: running in offline mode (using cached validation)",
					"edition", lic.Edition(),
					"days_remaining_in_grace_period", days,
				)
			}
			return lic
		}
		slog.Warn("license: local cache token is invalid or expired", "error", verr)
	}

	// ── 3. No valid cache and server unreachable → LITE ─────────────────────
	slog.Error("license: cannot validate license key — reverting to LITE edition",
		"key", maskKey(licenseKey),
		"reason", "server unreachable and no valid local cache found",
	)
	return liteOnly()
}

// validateOnline contacts the license server and returns the License and the
// raw signed JWT. Returns an error if the server is unreachable, rejects the
// key, or returns an unverifiable token.
func validateOnline(ctx context.Context, serverURL, key, fingerprint, version string) (*License, string, error) {
	body, err := json.Marshal(validateRequest{
		Key:         key,
		Fingerprint: fingerprint,
		Version:     version,
	})
	if err != nil {
		return nil, "", fmt.Errorf("marshaling request: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		serverURL+"/v1/validate", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("creating HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "metalwaf/"+version)

	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("contacting license server: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, "", fmt.Errorf("reading server response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("license server returned HTTP %d: %s", resp.StatusCode, respBody)
	}

	var vresp validateResponse
	if err := json.Unmarshal(respBody, &vresp); err != nil {
		return nil, "", fmt.Errorf("parsing server response: %w", err)
	}
	if !vresp.Valid {
		msg := vresp.Error
		if msg == "" {
			msg = "license key rejected by server"
		}
		return nil, "", errors.New(msg)
	}

	lic, err := verifyToken(vresp.Token)
	if err != nil {
		return nil, "", fmt.Errorf("verifying server-issued token: %w", err)
	}
	return lic, vresp.Token, nil
}

// verifyToken parses and cryptographically verifies the Ed25519-signed JWT
// returned by the license server.
//
// When serverPublicKeyHex is empty (source/dev builds), the signature check
// is skipped and a development-mode warning is logged.
func verifyToken(tokenStr string) (*License, error) {
	if serverPublicKeyHex == "" {
		// Development / source build: no embedded key → parse without verification.
		slog.Warn("license: server public key not set at build time — " +
			"JWT signature NOT verified (development mode). " +
			"Official MetalWAF binaries from metalwaf.io always verify signatures.")
		return parseUnverified(tokenStr)
	}

	pubBytes, err := hex.DecodeString(serverPublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding embedded public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("embedded public key has wrong length: got %d, expected %d",
			len(pubBytes), ed25519.PublicKeySize)
	}
	pubKey := ed25519.PublicKey(pubBytes)

	claims := &licenseClaims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected JWT signing method: %v", t.Header["alg"])
			}
			return pubKey, nil
		},
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}
	return claimsToLicense(claims), nil
}

// parseUnverified parses a JWT without checking its signature.
// Only used in development / source-compiled builds.
func parseUnverified(tokenStr string) (*License, error) {
	claims := &licenseClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tokenStr, claims)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT (unverified): %w", err)
	}
	return claimsToLicense(claims), nil
}

// claimsToLicense converts parsed JWT claims into a License value.
func claimsToLicense(c *licenseClaims) *License {
	lic := &License{
		ID:           c.LicenseID,
		CustomerName: c.CustomerName,
		Tier:         Tier(c.Tier),
		MaxSites:     c.MaxSites,
		LastChecked:  time.Now().UTC(),
	}
	if c.IssuedAt != nil {
		lic.IssuedAt = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		t := c.ExpiresAt.Time
		lic.ExpiresAt = &t
	}
	if lic.Tier == "" {
		lic.Tier = TierLite
	}
	return lic
}
