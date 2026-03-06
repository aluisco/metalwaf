package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"

	"github.com/google/uuid"
	"github.com/metalwaf/metalwaf/internal/database"
)

// ─── Mock store ───────────────────────────────────────────────────────────────

// mockStore is a minimal in-memory implementation of database.Store for tests.
// Methods that are not explicitly implemented will panic if called, helping
// detect unexpected calls.
type mockStore struct {
	database.Store // embedded nil interface — panics on unimplemented calls

	mu       sync.Mutex
	users    map[string]*database.User    // keyed by username
	sessions map[string]*database.Session // keyed by refreshToken (JTI)
}

func newMockStore() *mockStore {
	return &mockStore{
		users:    make(map[string]*database.User),
		sessions: make(map[string]*database.Session),
	}
}

func (m *mockStore) addUser(u *database.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.Username] = u
}

func (m *mockStore) GetUserByUsername(_ context.Context, username string) (*database.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.users[username], nil
}

func (m *mockStore) GetUserByID(_ context.Context, id string) (*database.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, nil
}

func (m *mockStore) UpdateUser(_ context.Context, u *database.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.Username] = u
	return nil
}

func (m *mockStore) CreateSession(_ context.Context, s *database.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.RefreshToken] = s
	return nil
}

func (m *mockStore) GetSessionByToken(_ context.Context, refreshToken string) (*database.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[refreshToken], nil
}

func (m *mockStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if s.ID == id {
			delete(m.sessions, k)
			return nil
		}
	}
	return nil
}

func (m *mockStore) DeleteSessionsByUserID(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, k)
		}
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const testPassword = "hunter2-testpassword-abc"

func newTestHandler(t *testing.T) (*Handler, *mockStore) {
	t.Helper()
	iss := newTestIssuer(t)
	store := newMockStore()
	h := NewHandler(store, iss)
	return h, store
}

func addTestUser(store *mockStore, username, password, role string) *database.User {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	u := &database.User{
		ID:           uuid.NewString(),
		Username:     username,
		Email:        username + "@test.invalid",
		PasswordHash: string(hash),
		Role:         role,
	}
	store.addUser(u)
	return u
}

func postJSON(t *testing.T, h http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func decodeResponse(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&m); err != nil {
		t.Fatalf("decoding response: %v — body: %s", err, rr.Body.String())
	}
	return m
}

// ─── Login ────────────────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	h, store := newTestHandler(t)
	addTestUser(store, "alice", testPassword, "admin")

	rr := postJSON(t, h.Login, "/api/v1/auth/login", map[string]string{
		"username": "alice",
		"password": testPassword,
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	body := decodeResponse(t, rr)
	if _, ok := body["access_token"]; !ok {
		t.Error("response missing access_token")
	}
	if _, ok := body["refresh_token"]; !ok {
		t.Error("response missing refresh_token")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	h, store := newTestHandler(t)
	addTestUser(store, "alice", testPassword, "admin")

	rr := postJSON(t, h.Login, "/api/v1/auth/login", map[string]string{
		"username": "alice",
		"password": "wrong-password!!!",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	body := decodeResponse(t, rr)
	if body["error"] != "invalid credentials" {
		t.Errorf("unexpected error message: %v", body["error"])
	}
}

func TestLogin_UserNotFound_SameErrorAsWrongPassword(t *testing.T) {
	h, _ := newTestHandler(t)
	// No users added to store.

	rr := postJSON(t, h.Login, "/api/v1/auth/login", map[string]string{
		"username": "ghost",
		"password": "somepassword",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	body := decodeResponse(t, rr)
	// Must return the same message as a wrong-password attempt (no username enumeration).
	if body["error"] != "invalid credentials" {
		t.Errorf("unexpected error message: %v", body["error"])
	}
}

func TestLogin_MissingCredentials(t *testing.T) {
	h, _ := newTestHandler(t)

	rr := postJSON(t, h.Login, "/api/v1/auth/login", map[string]string{
		"username": "alice",
		// password omitted
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestLogin_RateLimit(t *testing.T) {
	h, store := newTestHandler(t)
	addTestUser(store, "alice", testPassword, "admin")

	// The burst is 5. Exceed it from the same IP.
	// Use a static IP by setting RemoteAddr on the request.
	makeReq := func() *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"username": "alice", "password": "bad"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()
		h.Login(rr, req)
		return rr
	}

	// Drain the burst (5 attempts from same IP). They might return 401 (wrong creds).
	for i := 0; i < loginBurst; i++ {
		makeReq()
	}
	// The (loginBurst+1)-th attempt from the same IP must be rate-limited.
	rr := makeReq()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after burst is drained, got %d", rr.Code)
	}
}

// ─── Refresh ──────────────────────────────────────────────────────────────────

func loginAndGetTokens(t *testing.T, h *Handler, store *mockStore, username string) map[string]any {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": username, "password": testPassword})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.1.2.3:9999" // unique IP to avoid rate limit from other tests
	rr := httptest.NewRecorder()
	h.Login(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login failed with %d — body: %s", rr.Code, rr.Body.String())
	}
	var result map[string]any
	json.NewDecoder(rr.Body).Decode(&result)
	return result
}

func TestRefresh_Success(t *testing.T) {
	h, store := newTestHandler(t)
	addTestUser(store, "bob", testPassword, "viewer")

	tokens := loginAndGetTokens(t, h, store, "bob")
	refreshToken, _ := tokens["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("no refresh_token in login response")
	}

	rr := postJSON(t, h.Refresh, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	body := decodeResponse(t, rr)
	newAccess, _ := body["access_token"].(string)
	if newAccess == "" {
		t.Error("refresh did not return new access_token")
	}
	newRefresh, _ := body["refresh_token"].(string)
	if newRefresh == "" {
		t.Error("refresh did not return new refresh_token")
	}
	// Rotation: old refresh token must be gone.
	if newRefresh == refreshToken {
		t.Error("refresh token was not rotated")
	}
}

func TestRefresh_Replay_Rejected(t *testing.T) {
	h, store := newTestHandler(t)
	addTestUser(store, "carol", testPassword, "viewer")

	tokens := loginAndGetTokens(t, h, store, "carol")
	refreshToken, _ := tokens["refresh_token"].(string)

	// First refresh — should succeed.
	rr1 := postJSON(t, h.Refresh, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	})
	if rr1.Code != http.StatusOK {
		t.Fatalf("first refresh failed: %d", rr1.Code)
	}
	// Second refresh with the same (now revoked) token must fail.
	rr2 := postJSON(t, h.Refresh, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	})
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("replay attack: expected 401, got %d", rr2.Code)
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	h, _ := newTestHandler(t)

	rr := postJSON(t, h.Refresh, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": "this.is.garbage",
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ─── Logout ───────────────────────────────────────────────────────────────────

func TestLogout_Success(t *testing.T) {
	h, store := newTestHandler(t)
	addTestUser(store, "dave", testPassword, "viewer")

	tokens := loginAndGetTokens(t, h, store, "dave")
	refreshToken, _ := tokens["refresh_token"].(string)
	accessToken, _ := tokens["access_token"].(string)

	b, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	// Inject claims into context as RequireAuth would do.
	iss := newTestIssuer(t)
	claims, err := iss.ValidateAccessToken(accessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	req = req.WithContext(ClaimsToCtx(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.Logout(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", rr.Code, rr.Body.String())
	}

	// Session must be removed from the store.
	store.mu.Lock()
	count := len(store.sessions)
	store.mu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 sessions after logout, got %d", count)
	}
}

func TestLogoutAll_RemovesAllSessions(t *testing.T) {
	h, store := newTestHandler(t)
	addTestUser(store, "eve", testPassword, "viewer")

	// Login twice to create two sessions (different IPs to avoid rate limiting).
	makeLoginReq := func(remoteAddr string) string {
		b, _ := json.Marshal(map[string]string{"username": "eve", "password": testPassword})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remoteAddr
		rr := httptest.NewRecorder()
		h.Login(rr, req)
		var result map[string]any
		json.NewDecoder(rr.Body).Decode(&result)
		at, _ := result["access_token"].(string)
		return at
	}
	at1 := makeLoginReq("10.2.0.1:1")
	makeLoginReq("10.2.0.2:2")

	store.mu.Lock()
	if len(store.sessions) != 2 {
		store.mu.Unlock()
		t.Fatalf("expected 2 sessions, got %d", len(store.sessions))
	}
	store.mu.Unlock()

	iss := newTestIssuer(t)
	claims, _ := iss.ValidateAccessToken(at1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout-all", nil)
	req = req.WithContext(ClaimsToCtx(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.LogoutAll(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.sessions) != 0 {
		t.Errorf("expected 0 sessions after logout-all, got %d", len(store.sessions))
	}
}

// ─── RequireAuth middleware ───────────────────────────────────────────────────

func TestRequireAuth_MissingHeader_Returns401(t *testing.T) {
	iss := newTestIssuer(t)
	handler := iss.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestRequireAuth_ValidToken_Passes(t *testing.T) {
	iss := newTestIssuer(t)
	reached := false
	handler := iss.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		claims := ClaimsFromCtx(r.Context())
		if claims == nil {
			t.Error("claims not injected into context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	pair, _ := iss.IssueTokenPair("u1", "alice", "admin")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	if !reached {
		t.Error("inner handler was not called")
	}
}

func TestRequireAdmin_ViewerRole_Returns403(t *testing.T) {
	iss := newTestIssuer(t)
	handler := iss.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	pair, _ := iss.IssueTokenPair("u2", "bob", "viewer")
	req := httptest.NewRequest(http.MethodPost, "/admin-only", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer on admin route, got %d", rr.Code)
	}
}

func TestRequireAdmin_AdminRole_Passes(t *testing.T) {
	iss := newTestIssuer(t)
	handler := iss.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	pair, _ := iss.IssueTokenPair("u3", "charlie", "admin")
	req := httptest.NewRequest(http.MethodPost, "/admin-only", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin, got %d", rr.Code)
	}
}

// ─── TOTP setup flow ──────────────────────────────────────────────────────────

func TestTOTPSetup_GeneratesSecretAndURI(t *testing.T) {
	h, store := newTestHandler(t)
	u := addTestUser(store, "frank", testPassword, "admin")
	iss := newTestIssuer(t)
	pair, _ := iss.IssueTokenPair(u.ID, u.Username, u.Role)
	claims, _ := iss.ValidateAccessToken(pair.AccessToken)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/setup", nil)
	req = req.WithContext(ClaimsToCtx(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.TOTPSetup(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	body := decodeResponse(t, rr)
	secret, _ := body["secret"].(string)
	uri, _ := body["uri"].(string)
	if secret == "" {
		t.Error("expected non-empty TOTP secret in response")
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("unexpected URI format: %q", uri)
	}
}

// ─── Context helpers ──────────────────────────────────────────────────────────

// ClaimsToCtx injects claims into a context. This mirrors what RequireAuth
// does internally, and is needed by tests that skip the middleware layer.
func ClaimsToCtx(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey("auth_claims"), c)
}

// ─── loginLimiter: used to expose a reference limiter for testing ─────────────

func TestLoginLimiter_SameIPBlocksAfterBurst(t *testing.T) {
	lim := newLoginLimiter()
	ip := "192.168.1.100"

	allowed := 0
	for i := 0; i < loginBurst+2; i++ {
		if lim.allow(ip) {
			allowed++
		}
	}
	if allowed > loginBurst {
		t.Errorf("rate limiter allowed %d requests, burst is %d", allowed, loginBurst)
	}
}

func TestLoginLimiter_DifferentIPsAllowed(t *testing.T) {
	lim := newLoginLimiter()

	// Two distinct IPs should each get their own limiter.
	for i := 0; i < loginBurst; i++ {
		if !lim.allow("1.2.3.4") {
			t.Error("IP 1.2.3.4 should be allowed")
		}
		if !lim.allow("5.6.7.8") {
			t.Error("IP 5.6.7.8 should be allowed")
		}
	}
}

func TestLoginLimiter_Cleanup(t *testing.T) {
	lim := newLoginLimiter()

	// Pre-populate the map with stale entries (lastSeen > 10 minutes ago).
	// Use fmt.Sprintf to guarantee each key is unique.
	lim.mu.Lock()
	for i := 0; i < limiterCleanupThreshold+50; i++ {
		key := fmt.Sprintf("10.%d.%d.%d", i>>16&0xFF, i>>8&0xFF, i&0xFF)
		lim.ips[key] = &ipEntry{
			lim:      rate.NewLimiter(loginRatePerSec, loginBurst),
			lastSeen: time.Now().Add(-15 * time.Minute), // older than the 10-min cutoff
		}
	}
	lim.mu.Unlock()

	// Trigger allow() — since len > threshold, the cleanup sweep runs.
	lim.allow("1.1.1.1")

	lim.mu.Lock()
	n := len(lim.ips)
	lim.mu.Unlock()

	// All stale entries should be gone; only "1.1.1.1" (just added) remains.
	if n > 1 {
		t.Errorf("cleanup did not remove stale entries: got %d remaining", n)
	}
}
