package proxy

import (
	"net"
	"net/http"
	"strings"
)

// requestHeadersToDrop are headers the client might send to spoof identity.
// They are deleted before the proxy adds the authoritative versions.
var requestHeadersToDrop = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Original-Forwarded-For",
}

// responseHeadersToDrop are upstream response headers that reveal backend
// technology details and should not be visible to end clients.
var responseHeadersToDrop = []string{
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
}

// setForwardHeaders removes any client-supplied forwarding headers (to prevent
// spoofing) and writes the authoritative X-Forwarded-* and X-Real-IP headers.
// clientIP is the verified remote address of the original client.
// proto is the scheme ("http" or "https") used by the original connection.
func setForwardHeaders(r *http.Request, clientIP, proto string) {
	for _, h := range requestHeadersToDrop {
		r.Header.Del(h)
	}
	r.Header.Set("X-Real-IP", clientIP)
	r.Header.Set("X-Forwarded-For", clientIP)
	r.Header.Set("X-Forwarded-Proto", proto)
	r.Header.Set("X-Forwarded-Host", r.Host)
}

// stripResponseHeaders removes sensitive headers from an upstream response
// before forwarding it to the client.
func stripResponseHeaders(h http.Header) {
	for _, name := range responseHeadersToDrop {
		h.Del(name)
	}
}

// clientIP extracts the IP address (without port) from r.RemoteAddr.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// isWebSocketUpgrade reports whether the request is a WebSocket upgrade.
// httputil.ReverseProxy handles WebSocket proxying automatically when this
// header is present, so no special handling is required.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// stripPort removes the port part from a host string.
// Examples:
//
//	"example.com:8080" → "example.com"
//	"[::1]:443"        → "[::1]"
//	"example.com"      → "example.com"
func stripPort(host string) string {
	if strings.HasPrefix(host, "[") {
		// IPv6 bracket notation: [::1]:8080 → [::1]
		if end := strings.LastIndex(host, "]:"); end != -1 {
			return host[:end+1]
		}
		return host
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}
