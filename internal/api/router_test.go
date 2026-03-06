package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
	"github.com/metalwaf/metalwaf/internal/api"
	"github.com/metalwaf/metalwaf/internal/auth"
	"github.com/metalwaf/metalwaf/internal/database"
)

// ─── Mock store ───────────────────────────────────────────────────────────────

// routerMockStore is a minimal database.Store for router integration tests.
// Only the methods exercised by the tested routes are implemented.
// Calling any unimplemented method panics, helping catch unexpected store use.
type routerMockStore struct {
	database.Store // embedded nil — panics on unimplemented calls

	mu       sync.Mutex
	users    map[string]*database.User    // keyed by username
	sessions map[string]*database.Session // keyed by refreshToken JTI
	sites    []*database.Site
	settings map[string]string
}

func newRouterMockStore() *routerMockStore {
	return &routerMockStore{
		users:    make(map[string]*database.User),
		sessions: make(map[string]*database.Session),
		settings: make(map[string]string),
	}
}

func (m *routerMockStore) addUser(u *database.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.Username] = u
}

func (m *routerMockStore) GetUserByUsername(_ context.Context, username string) (*database.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.users[username], nil
}

func (m *routerMockStore) GetUserByID(_ context.Context, id string) (*database.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, nil
}

func (m *routerMockStore) UpdateUser(_ context.Context, u *database.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.Username] = u
	return nil
}

func (m *routerMockStore) CreateSession(_ context.Context, s *database.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.RefreshToken] = s
	return nil
}

func (m *routerMockStore) GetSessionByToken(_ context.Context, refreshToken string) (*database.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[refreshToken], nil
}

func (m *routerMockStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if s.ID == id {
			delete(m.sessions, k)
		}
	}
	return nil
}

func (m *routerMockStore) DeleteSessionsByUserID(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, k)
		}
	}
	return nil
}

func (m *routerMockStore) ListSites(_ context.Context) ([]*database.Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sites, nil
}

func (m *routerMockStore) ListWAFRules(_ context.Context, _ *string) ([]*database.WAFRule, error) {
	return []*database.WAFRule{}, nil
}

func (m *routerMockStore) GetAllSettings(_ context.Context) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.settings))
	for k, v := range m.settings {
		out[k] = v
	}
	return out, nil
}

func (m *routerMockStore) CountRequestLogs(_ context.Context, _ database.RequestLogFilter) (int64, error) {
	return 0, nil
}

func (m *routerMockStore) ListRequestLogs(_ context.Context, _ database.RequestLogFilter) ([]*database.RequestLog, error) {
	return []*database.RequestLog{}, nil
}

func (m *routerMockStore) ListCertificates(_ context.Context) ([]*database.Certificate, error) {
	return []*database.Certificate{}, nil
}

// ─── Test fixtures ────────────────────────────────────────────────────────────

const routerTestSecret = "router-test-secret-that-is-long-enough-abc123"

func newRouterTestIssuer(t *testing.T) *auth.Issuer {
	t.Helper()
	iss, err := auth.NewIssuer(routerTestSecret, 15, 7)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

func setupRouter(t *testing.T) (http.Handler, *routerMockStore, *auth.Issuer) {
	t.Helper()
	store := newRouterMockStore()
	iss := newRouterTestIssuer(t)

	// Pre-compute bcrypt at MinCost for test speed.
	adminHash, _ := bcrypt.GenerateFromPassword([]byte("admin-secret-password"), bcrypt.MinCost)
	viewerHash, _ := bcrypt.GenerateFromPassword([]byte("viewer-secret-pass"), bcrypt.MinCost)

	store.addUser(&database.User{
		ID:           uuid.NewString(),
		Username:     "adminuser",
		PasswordHash: string(adminHash),
		Role:         "admin",
	})
	store.addUser(&database.User{
		ID:           uuid.NewString(),
		Username:     "vieweruser",
		PasswordHash: string(viewerHash),
		Role:         "viewer",
	})

	router := api.NewRouter(api.Options{
		Store:  store,
		Issuer: iss,
	})
	return router, store, iss
}

func doRequest(t *testing.T, router http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.RemoteAddr = "127.0.0.1:9000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func loginAs(t *testing.T, router http.Handler, username, password string) (accessToken, refreshToken string) {
	t.Helper()
	rr := doRequest(t, router, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": username, "password": password}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("login failed for %q: %d — %s", username, rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	accessToken, _ = resp["access_token"].(string)
	refreshToken, _ = resp["refresh_token"].(string)
	return
}

// ─── Login endpoint ───────────────────────────────────────────────────────────

func TestRouter_Login_ReturnsTokens(t *testing.T) {
	router, _, _ := setupRouter(t)

	rr := doRequest(t, router, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": "adminuser", "password": "admin-secret-password"}, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["access_token"] == nil {
		t.Error("missing access_token")
	}
	if resp["refresh_token"] == nil {
		t.Error("missing refresh_token")
	}
	if resp["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", resp["role"])
	}
}

func TestRouter_Login_WrongPassword_Returns401(t *testing.T) {
	router, _, _ := setupRouter(t)

	rr := doRequest(t, router, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": "adminuser", "password": "wrong!"}, "")

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ─── Authentication enforcement ───────────────────────────────────────────────

func TestRouter_ProtectedRoute_NoToken_Returns401(t *testing.T) {
	router, _, _ := setupRouter(t)

	rr := doRequest(t, router, http.MethodGet, "/api/v1/sites", nil, "" /* no token */)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d — body: %s", rr.Code, rr.Body.String())
	}
}

func TestRouter_ProtectedRoute_ValidViewerToken_Returns200(t *testing.T) {
	router, _, _ := setupRouter(t)

	at, _ := loginAs(t, router, "vieweruser", "viewer-secret-pass")

	rr := doRequest(t, router, http.MethodGet, "/api/v1/sites", nil, at)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
}

// ─── Role enforcement ─────────────────────────────────────────────────────────

func TestRouter_AdminRoute_ViewerToken_Returns403(t *testing.T) {
	router, _, _ := setupRouter(t)

	at, _ := loginAs(t, router, "vieweruser", "viewer-secret-pass")

	// GET /api/v1/settings requires admin.
	rr := doRequest(t, router, http.MethodGet, "/api/v1/settings", nil, at)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer on admin route, got %d — body: %s",
			rr.Code, rr.Body.String())
	}
}

func TestRouter_AdminRoute_AdminToken_Returns200(t *testing.T) {
	router, _, _ := setupRouter(t)

	at, _ := loginAs(t, router, "adminuser", "admin-secret-password")

	rr := doRequest(t, router, http.MethodGet, "/api/v1/settings", nil, at)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin on settings route, got %d — body: %s",
			rr.Code, rr.Body.String())
	}
}

func TestRouter_SitesRead_ViewerAllowed(t *testing.T) {
	router, _, _ := setupRouter(t)
	at, _ := loginAs(t, router, "vieweruser", "viewer-secret-pass")

	rr := doRequest(t, router, http.MethodGet, "/api/v1/rules", nil, at)
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer should be able to list rules: got %d", rr.Code)
	}
}

// ─── Security headers ─────────────────────────────────────────────────────────

func TestRouter_SecurityHeaders_Present(t *testing.T) {
	router, _, _ := setupRouter(t)

	// Even a 401 response should carry security headers.
	rr := doRequest(t, router, http.MethodGet, "/api/v1/sites", nil, "")

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for name, want := range headers {
		got := rr.Header().Get(name)
		if got != want {
			t.Errorf("header %q: got %q, want %q", name, got, want)
		}
	}
	cacheControl := rr.Header().Get("Cache-Control")
	if cacheControl == "" {
		t.Error("Cache-Control header missing")
	}
}

// ─── Certificates stub ────────────────────────────────────────────────────────

func TestRouter_CertificatesStub_ReturnsEmptyArray(t *testing.T) {
	router, _, _ := setupRouter(t)
	at, _ := loginAs(t, router, "vieweruser", "viewer-secret-pass")

	rr := doRequest(t, router, http.MethodGet, "/api/v1/certificates", nil, at)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	// Body must be JSON with a "data" key that is an empty array.
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	data, ok := resp["data"]
	if !ok {
		t.Fatal("response missing 'data' key")
	}
	arr, ok := data.([]any)
	if !ok {
		t.Fatalf("'data' should be an array, got %T", data)
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array, got len=%d", len(arr))
	}
}

// ─── Metrics endpoint ─────────────────────────────────────────────────────────

func TestRouter_Metrics_ReturnsExpectedShape(t *testing.T) {
	router, _, _ := setupRouter(t)
	at, _ := loginAs(t, router, "vieweruser", "viewer-secret-pass")

	rr := doRequest(t, router, http.MethodGet, "/api/v1/metrics", nil, at)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("'data' missing or not object: %v", resp)
	}
	requiredFields := []string{"requests_total", "requests_24h", "blocked_total", "blocked_24h", "generated_at"}
	for _, f := range requiredFields {
		if _, ok := data[f]; !ok {
			t.Errorf("metrics response missing field %q", f)
		}
	}
}

// ─── Token refresh via router ─────────────────────────────────────────────────

func TestRouter_Refresh_ReturnsNewTokens(t *testing.T) {
	router, _, _ := setupRouter(t)

	_, rt := loginAs(t, router, "adminuser", "admin-secret-password")

	rr := doRequest(t, router, http.MethodPost, "/api/v1/auth/refresh",
		map[string]string{"refresh_token": rt}, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["access_token"] == nil {
		t.Error("refresh did not return access_token")
	}
}

// ─── Envelope format ─────────────────────────────────────────────────────────

func TestRouter_ListSites_ResponseEnvelope(t *testing.T) {
	router, _, _ := setupRouter(t)
	at, _ := loginAs(t, router, "vieweruser", "viewer-secret-pass")

	rr := doRequest(t, router, http.MethodGet, "/api/v1/sites", nil, at)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if _, ok := resp["data"]; !ok {
		t.Error("response should be wrapped in {\"data\": ...} envelope")
	}
	if _, ok := resp["error"]; ok {
		t.Error("successful response should not contain 'error' key")
	}
}

func TestRouter_UnauthorizedResponse_EnvelopeFormat(t *testing.T) {
	router, _, _ := setupRouter(t)

	rr := doRequest(t, router, http.MethodGet, "/api/v1/sites", nil, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding 401 response: %v", err)
	}
	if resp["error"] == nil {
		t.Error("401 response should contain 'error' key")
	}
}

// ─── Logs endpoint ────────────────────────────────────────────────────────────

func TestRouter_Logs_ReturnsShape(t *testing.T) {
	router, _, _ := setupRouter(t)
	at, _ := loginAs(t, router, "vieweruser", "viewer-secret-pass")

	rr := doRequest(t, router, http.MethodGet, "/api/v1/logs", nil, at)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	data, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object, got: %v", resp)
	}
	if _, ok := data["logs"]; !ok {
		t.Error("expected 'logs' field in data")
	}
	if _, ok := data["total"]; !ok {
		t.Error("expected 'total' field in data")
	}
}

// ─── Expired/tampered token ───────────────────────────────────────────────────

func TestRouter_TamperedToken_Returns401(t *testing.T) {
	router, _, _ := setupRouter(t)
	at, _ := loginAs(t, router, "vieweruser", "viewer-secret-pass")

	// Tamper with the signature by appending "X" to the token.
	tamperedToken := at + "X"
	rr := doRequest(t, router, http.MethodGet, "/api/v1/sites", nil, tamperedToken)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("tampered token should return 401, got %d", rr.Code)
	}
}

// ensure time import is not removed by the go compiler
var _ = time.Now
