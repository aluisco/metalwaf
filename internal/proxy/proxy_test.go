package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/metalwaf/metalwaf/internal/database"
)

// mockStore is a minimal in-memory Store for proxy tests.
// Only ListSites and ListUpstreamsBySite are implemented; calling any other
// method will panic (acceptable — tests control which methods are invoked).
type mockStore struct {
	database.Store // embedded nil interface for unimplemented methods
	sites          []*database.Site
	upstreams      map[string][]*database.Upstream // siteID → []Upstream
}

func (m *mockStore) ListSites(_ context.Context) ([]*database.Site, error) {
	return m.sites, nil
}

func (m *mockStore) ListUpstreamsBySite(_ context.Context, siteID string) ([]*database.Upstream, error) {
	return m.upstreams[siteID], nil
}

// newTestHandler builds a Handler from the given mock store.
func newTestHandler(t *testing.T, store *mockStore) *Handler {
	t.Helper()
	h, err := New(context.Background(), store)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return h
}

func TestHandler_SiteNotFound(t *testing.T) {
	h := newTestHandler(t, &mockStore{sites: []*database.Site{}})

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
	req.Host = "unknown.example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestHandler_DisabledSiteNotFound(t *testing.T) {
	h := newTestHandler(t, &mockStore{
		sites: []*database.Site{{
			ID:      "site-1",
			Domain:  "example.com",
			Enabled: false, // disabled — should not be routed
		}},
		upstreams: map[string][]*database.Upstream{},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("disabled site: status = %d, want 404", rr.Code)
	}
}

func TestHandler_HTTPSOnlyRedirect(t *testing.T) {
	h := newTestHandler(t, &mockStore{
		sites: []*database.Site{{
			ID:        "site-1",
			Domain:    "example.com",
			HTTPSOnly: true,
			Enabled:   true,
		}},
		upstreams: map[string][]*database.Upstream{"site-1": {}},
	})

	// Plain HTTP request — r.TLS == nil.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?q=1", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://") {
		t.Errorf("Location = %q, want https:// prefix", loc)
	}
	if !strings.Contains(loc, "/path?q=1") {
		t.Errorf("Location = %q, should preserve path and query", loc)
	}
}

func TestHandler_NoHealthyUpstreams_Returns503(t *testing.T) {
	h := newTestHandler(t, &mockStore{
		sites: []*database.Site{{
			ID:      "site-1",
			Domain:  "example.com",
			Enabled: true,
		}},
		// Empty upstream list → pool.Next() returns nil.
		upstreams: map[string][]*database.Upstream{"site-1": {}},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestHandler_ProxiesToUpstream(t *testing.T) {
	// Start a test upstream server that echoes a fixed body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that forwarding headers were set.
		if r.Header.Get("X-Real-IP") == "" {
			t.Error("upstream did not receive X-Real-IP header")
		}
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Error("upstream did not receive X-Forwarded-For header")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from upstream")) //nolint:errcheck
	}))
	defer upstream.Close()

	h := newTestHandler(t, &mockStore{
		sites: []*database.Site{{
			ID:      "site-1",
			Domain:  "example.com",
			Enabled: true,
		}},
		upstreams: map[string][]*database.Upstream{
			"site-1": {{
				ID:      "up-1",
				SiteID:  "site-1",
				URL:     upstream.URL,
				Weight:  1,
				Enabled: true,
			}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "hello from upstream") {
		t.Errorf("unexpected body: %q", rr.Body.String())
	}
}

func TestHandler_HostMatchIsCaseInsensitive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := newTestHandler(t, &mockStore{
		sites: []*database.Site{{
			ID:      "site-1",
			Domain:  "Example.COM", // stored with mixed case
			Enabled: true,
		}},
		upstreams: map[string][]*database.Upstream{
			"site-1": {{ID: "up-1", SiteID: "site-1", URL: upstream.URL, Weight: 1, Enabled: true}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://EXAMPLE.com/", nil)
	req.Host = "EXAMPLE.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("case-insensitive host match failed: status = %d", rr.Code)
	}
}
