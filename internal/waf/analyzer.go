package waf

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// maxBodyBytes is the maximum number of bytes read from the request body for
// WAF inspection. The body is always restored so the proxy can forward it.
const maxBodyBytes = 512 * 1024 // 512 KB

// Fields holds the extracted, inspectable parts of an HTTP request.
type Fields struct {
	URI       string
	Query     string
	Body      string
	IP        string
	UserAgent string
	Method    string
	Headers   http.Header
}

// Extract reads the request fields needed for WAF inspection.
//
// Body handling: the first maxBodyBytes are read into a buffer for inspection.
// The body reader is then reconstructed as buffer+rest-of-stream so the
// reverse proxy can still forward the complete body to the upstream.
func Extract(r *http.Request) *Fields {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	var body string
	if r.Body != nil && r.Body != http.NoBody {
		buf, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		// Reconstruct: buf already read + whatever remains in the original stream.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
		body = string(buf)
	}

	// URL-decode the query string so that patterns using \s, letters, etc.
	// match regardless of whether the attacker used +, %20, or raw spaces.
	// This also normalises double-encoded sequences one level.
	query := r.URL.RawQuery
	if decoded, err := url.QueryUnescape(query); err == nil {
		query = decoded
	}

	return &Fields{
		URI:       r.URL.Path,
		Query:     query,
		Body:      body,
		IP:        ip,
		UserAgent: r.Header.Get("User-Agent"),
		Method:    r.Method,
		Headers:   r.Header,
	}
}

// getValue returns the value of the given field name from f.
// Header fields use the "header:<name>" notation.
func (f *Fields) getValue(field string) string {
	switch field {
	case FieldURI:
		return f.URI
	case FieldQuery:
		return f.Query
	case FieldBody:
		return f.Body
	case FieldIP:
		return f.IP
	case FieldUserAgent:
		return f.UserAgent
	case FieldMethod:
		return f.Method
	default:
		if strings.HasPrefix(field, "header:") {
			return f.Headers.Get(strings.TrimPrefix(field, "header:"))
		}
		return ""
	}
}
