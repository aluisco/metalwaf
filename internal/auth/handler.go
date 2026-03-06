package auth

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"

	"github.com/google/uuid"
	"github.com/metalwaf/metalwaf/internal/database"
)

// Login rate-limit parameters.
// 5 attempts per 2 minutes per IP; burst allows short bursts up to 5.
const (
	loginRatePerSec = rate.Limit(5.0 / 120.0) // 5 per 2 min
	loginBurst      = 5
)

// Handler handles all /api/v1/auth/* routes.
type Handler struct {
	store   database.Store
	issuer  *Issuer
	limiter *loginLimiter
	// dummyHash is a pre-computed bcrypt hash used when a username is not
	// found, ensuring login timing is indistinguishable from a wrong-password
	// attempt (prevents username enumeration via response-time analysis).
	dummyHash []byte
}

// NewHandler creates a Handler and pre-computes the dummy bcrypt hash.
// The bcrypt work factor ensures the pre-computation takes ~100ms at startup.
func NewHandler(store database.Store, issuer *Issuer) *Handler {
	dummy, _ := bcrypt.GenerateFromPassword(
		[]byte("metalwaf-timing-dummy-password-do-not-use"),
		bcrypt.DefaultCost,
	)
	return &Handler{
		store:     store,
		issuer:    issuer,
		limiter:   newLoginLimiter(),
		dummyHash: dummy,
	}
}

// ─── Login ────────────────────────────────────────────────────────────────────

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"` // required only if 2FA is enabled
}

type loginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Role         string    `json:"role"`
}

// Login handles POST /api/v1/auth/login.
//
// Security properties:
//   - Per-IP rate limiting prevents brute-force attacks.
//   - bcrypt comparison is always performed (even for non-existent users) to
//     prevent username enumeration via timing side-channels.
//   - Failed and successful logins return the same error message for bad
//     credentials, preventing username enumeration via response content.
//   - If TOTP is enabled for the user, a valid code is required.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	if !h.limiter.allow(ip) {
		writeAuthJSON(w, http.StatusTooManyRequests,
			map[string]string{"error": "too many login attempts — please wait before retrying"})
		return
	}

	var req loginRequest
	if err := decodeBody(r, &req, 512); err != nil {
		writeAuthJSON(w, http.StatusBadRequest,
			map[string]string{"error": "invalid request body"})
		return
	}
	if req.Username == "" || req.Password == "" {
		writeAuthJSON(w, http.StatusBadRequest,
			map[string]string{"error": "username and password are required"})
		return
	}

	const credFail = "invalid credentials"

	user, err := h.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		slog.Error("auth: user lookup", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	if user == nil {
		// Username not found — still run bcrypt to equalise timing.
		_ = bcrypt.CompareHashAndPassword(h.dummyHash, []byte(req.Password))
		writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": credFail})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": credFail})
		return
	}

	// TOTP check — only when 2FA is enabled for this user.
	if user.TOTPEnabled {
		if req.TOTPCode == "" {
			writeAuthJSON(w, http.StatusUnauthorized, map[string]any{
				"error":         credFail,
				"totp_required": true,
			})
			return
		}
		if !ValidateTOTP(req.TOTPCode, user.TOTPSecret) {
			writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": credFail})
			return
		}
	}

	pair, err := h.issuer.IssueTokenPair(user.ID, user.Username, user.Role)
	if err != nil {
		slog.Error("auth: issuing token pair", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	sess := &database.Session{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		RefreshToken: pair.RefreshJTI, // store JTI, not the full JWT
		ExpiresAt:    time.Now().UTC().Add(h.issuer.RefreshDuration()),
		IPAddress:    ip,
		UserAgent:    r.Header.Get("User-Agent"),
	}
	if err := h.store.CreateSession(r.Context(), sess); err != nil {
		slog.Error("auth: creating session", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	slog.Info("auth: login", "user", user.Username, "ip", ip)
	writeAuthJSON(w, http.StatusOK, loginResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    pair.AccessExpiry,
		Role:         user.Role,
	})
}

// ─── Refresh ──────────────────────────────────────────────────────────────────

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh handles POST /api/v1/auth/refresh.
//
// Implements refresh token rotation: the presented refresh token is revoked
// and a new pair is issued. Replay detection: after a token is used, any
// subsequent attempt to use the same token will fail because the session row
// no longer exists in the database.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeBody(r, &req, 2048); err != nil {
		writeAuthJSON(w, http.StatusBadRequest,
			map[string]string{"error": "invalid request body"})
		return
	}

	claims, err := h.issuer.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		writeAuthJSON(w, http.StatusUnauthorized,
			map[string]string{"error": "invalid or expired refresh token"})
		return
	}

	// Look up session by jti stored in DB.
	sess, err := h.store.GetSessionByToken(r.Context(), claims.ID)
	if err != nil || sess == nil {
		writeAuthJSON(w, http.StatusUnauthorized,
			map[string]string{"error": "session not found or already revoked"})
		return
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		_ = h.store.DeleteSession(r.Context(), sess.ID)
		writeAuthJSON(w, http.StatusUnauthorized,
			map[string]string{"error": "session expired"})
		return
	}

	// Rotate: delete old session before issuing new pair.
	if err := h.store.DeleteSession(r.Context(), sess.ID); err != nil {
		slog.Error("auth: revoking old session", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	// Re-read user to pick up any role / status changes since last login.
	user, err := h.store.GetUserByID(r.Context(), claims.UserID)
	if err != nil || user == nil {
		writeAuthJSON(w, http.StatusUnauthorized,
			map[string]string{"error": "user not found"})
		return
	}

	pair, err := h.issuer.IssueTokenPair(user.ID, user.Username, user.Role)
	if err != nil {
		slog.Error("auth: issuing refreshed token pair", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	newSess := &database.Session{
		UserID:       user.ID,
		RefreshToken: pair.RefreshJTI,
		ExpiresAt:    time.Now().UTC().Add(h.issuer.RefreshDuration()),
		IPAddress:    clientIP(r),
		UserAgent:    r.Header.Get("User-Agent"),
	}
	if err := h.store.CreateSession(r.Context(), newSess); err != nil {
		slog.Error("auth: creating refreshed session", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	writeAuthJSON(w, http.StatusOK, loginResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    pair.AccessExpiry,
		Role:         user.Role,
	})
}

// ─── Logout ───────────────────────────────────────────────────────────────────

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Logout handles POST /api/v1/auth/logout.
// The access token is validated by RequireAuth middleware before this runs.
// Deletes the session corresponding to the provided refresh token.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	_ = decodeBody(r, &req, 2048) // best-effort; we still proceed on decode error

	if req.RefreshToken != "" {
		if claims, err := h.issuer.ValidateRefreshToken(req.RefreshToken); err == nil {
			if sess, _ := h.store.GetSessionByToken(r.Context(), claims.ID); sess != nil {
				_ = h.store.DeleteSession(r.Context(), sess.ID)
			}
		}
	}

	c := ClaimsFromCtx(r.Context())
	if c != nil {
		slog.Info("auth: logout", "user_id", c.UserID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// LogoutAll handles POST /api/v1/auth/logout-all.
// Revokes ALL active sessions for the authenticated user across all devices.
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	c := ClaimsFromCtx(r.Context())
	if c == nil {
		writeAuthJSON(w, http.StatusUnauthorized,
			map[string]string{"error": "not authenticated"})
		return
	}
	if err := h.store.DeleteSessionsByUserID(r.Context(), c.UserID); err != nil {
		slog.Error("auth: logout-all error", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}
	slog.Info("auth: all sessions revoked", "user_id", c.UserID)
	w.WriteHeader(http.StatusNoContent)
}

// ─── TOTP ─────────────────────────────────────────────────────────────────────

type totpSetupResp struct {
	Secret string `json:"secret"` // base32 — shown once, then obscured
	URI    string `json:"uri"`    // otpauth:// URI for QR code generation
}

// TOTPSetup handles POST /api/v1/auth/totp/setup.
// Generates a new TOTP secret and stores it for the authenticated user.
// 2FA is NOT yet active; the user must call TOTPVerify to confirm and enable it.
func (h *Handler) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	c := ClaimsFromCtx(r.Context())
	if c == nil {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}

	user, err := h.store.GetUserByID(r.Context(), c.UserID)
	if err != nil || user == nil {
		writeAuthJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		slog.Error("auth: generating TOTP secret", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	// Store secret but do NOT enable yet — requires verification first.
	user.TOTPSecret = secret
	user.TOTPEnabled = false
	if err := h.store.UpdateUser(r.Context(), user); err != nil {
		slog.Error("auth: saving TOTP secret", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	writeAuthJSON(w, http.StatusOK, totpSetupResp{
		Secret: secret,
		URI:    TOTPUri(secret, "MetalWAF", user.Username),
	})
}

type totpCodeRequest struct {
	Code string `json:"code"`
}

// TOTPVerify handles POST /api/v1/auth/totp/verify.
// Validates the provided 6-digit code against the pending secret and enables 2FA.
func (h *Handler) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	c := ClaimsFromCtx(r.Context())
	if c == nil {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}

	var req totpCodeRequest
	if err := decodeBody(r, &req, 64); err != nil {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	user, err := h.store.GetUserByID(r.Context(), c.UserID)
	if err != nil || user == nil {
		writeAuthJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if user.TOTPSecret == "" {
		writeAuthJSON(w, http.StatusBadRequest,
			map[string]string{"error": "TOTP not configured — call POST /api/v1/auth/totp/setup first"})
		return
	}
	if !ValidateTOTP(req.Code, user.TOTPSecret) {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid TOTP code"})
		return
	}

	user.TOTPEnabled = true
	if err := h.store.UpdateUser(r.Context(), user); err != nil {
		slog.Error("auth: enabling TOTP", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	slog.Info("auth: 2FA enabled", "user_id", user.ID)
	writeAuthJSON(w, http.StatusOK, map[string]string{"message": "2FA enabled successfully"})
}

// TOTPDisable handles POST /api/v1/auth/totp/disable.
// Requires a valid TOTP code to prevent accidental or unauthorised disable.
func (h *Handler) TOTPDisable(w http.ResponseWriter, r *http.Request) {
	c := ClaimsFromCtx(r.Context())
	if c == nil {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}

	var req totpCodeRequest
	if err := decodeBody(r, &req, 64); err != nil {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	user, err := h.store.GetUserByID(r.Context(), c.UserID)
	if err != nil || user == nil {
		writeAuthJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if !user.TOTPEnabled {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "2FA is not enabled"})
		return
	}
	if !ValidateTOTP(req.Code, user.TOTPSecret) {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid TOTP code"})
		return
	}

	user.TOTPEnabled = false
	user.TOTPSecret = ""
	if err := h.store.UpdateUser(r.Context(), user); err != nil {
		slog.Error("auth: disabling TOTP", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "internal server error"})
		return
	}

	slog.Info("auth: 2FA disabled", "user_id", user.ID)
	writeAuthJSON(w, http.StatusOK, map[string]string{"message": "2FA disabled"})
}

// ─── Per-IP login rate limiter ─────────────────────────────────────────────────

type ipEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

type loginLimiter struct {
	mu  sync.Mutex
	ips map[string]*ipEntry
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{ips: make(map[string]*ipEntry)}
}

// limiterCleanupThreshold is the number of per-IP entries that triggers a
// lazy sweep of stale entries from the rate-limiter map.
const limiterCleanupThreshold = 10_000

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Lazy cleanup when the table grows large (prevents unbounded memory use
	// under IP-cycling attacks without requiring a background goroutine).
	if len(l.ips) > limiterCleanupThreshold {
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, v := range l.ips {
			if v.lastSeen.Before(cutoff) {
				delete(l.ips, k)
			}
		}
	}

	e, ok := l.ips[ip]
	if !ok {
		e = &ipEntry{lim: rate.NewLimiter(loginRatePerSec, loginBurst)}
		l.ips[ip] = e
	}
	e.lastSeen = time.Now()
	return e.lim.Allow()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// decodeBody decodes a JSON request body, enforcing a maximum byte size.
func decodeBody(r *http.Request, dst any, maxBytes int64) error {
	if r.Body == nil {
		return errors.New("empty request body")
	}
	return json.NewDecoder(io.LimitReader(r.Body, maxBytes)).Decode(dst)
}

// clientIP extracts the client IP from RemoteAddr, stripping the port.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
