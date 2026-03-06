package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetForwardHeaders_SetsHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	setForwardHeaders(req, "1.2.3.4", "https")

	if got := req.Header.Get("X-Real-IP"); got != "1.2.3.4" {
		t.Errorf("X-Real-IP = %q, want %q", got, "1.2.3.4")
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "1.2.3.4" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "1.2.3.4")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "example.com")
	}
}

func TestSetForwardHeaders_DropsSpoofedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	// Attacker tries to spoof its origin.
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Real-IP", "10.0.0.1")

	setForwardHeaders(req, "1.2.3.4", "http")

	if got := req.Header.Get("X-Real-IP"); got != "1.2.3.4" {
		t.Errorf("X-Real-IP not overwritten: got %q, want %q", got, "1.2.3.4")
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "1.2.3.4" {
		t.Errorf("X-Forwarded-For not overwritten: got %q, want %q", got, "1.2.3.4")
	}
}

func TestStripResponseHeaders_RemovesSensitive(t *testing.T) {
	h := http.Header{}
	h.Set("X-Powered-By", "PHP/8.2")
	h.Set("X-AspNet-Version", "4.0.0")
	h.Set("X-AspNetMvc-Version", "5.0")
	h.Set("Content-Type", "application/json")

	stripResponseHeaders(h)

	for _, name := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if h.Get(name) != "" {
			t.Errorf("%s should have been stripped", name)
		}
	}
	if h.Get("Content-Type") == "" {
		t.Error("Content-Type should NOT have been stripped")
	}
}

func TestClientIP_WithPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"

	if got := clientIP(req); got != "192.168.1.100" {
		t.Errorf("clientIP = %q, want %q", got, "192.168.1.100")
	}
}

func TestClientIP_IPv6WithPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:8080"

	if got := clientIP(req); got != "::1" {
		t.Errorf("clientIP = %q, want %q", got, "::1")
	}
}

func TestStripPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:443", "[::1]"},
		{"[::1]", "[::1]"},
		{"localhost:9090", "localhost"},
	}
	for _, c := range cases {
		if got := stripPort(c.in); got != c.want {
			t.Errorf("stripPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	if isWebSocketUpgrade(req) {
		t.Error("should not be WebSocket without Upgrade header")
	}
	req.Header.Set("Upgrade", "websocket")
	if !isWebSocketUpgrade(req) {
		t.Error("should be WebSocket with Upgrade: websocket")
	}
	req.Header.Set("Upgrade", "WebSocket") // case-insensitive
	if !isWebSocketUpgrade(req) {
		t.Error("should be WebSocket with Upgrade: WebSocket (case-insensitive)")
	}
}
