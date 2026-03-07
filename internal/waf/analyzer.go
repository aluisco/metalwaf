package waf

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
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
//
// Binary content types (application/octet-stream, application/pdf, image/*,
// audio/*, video/*, etc.) are never read — they cannot carry text-based
// injection payloads and binary bytes produce false positives.
// multipart/form-data bodies are partially parsed: only text (non-file) fields
// are extracted for inspection; file parts are skipped.
func Extract(r *http.Request) *Fields {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	var body string
	if r.Body != nil && r.Body != http.NoBody {
		ct := r.Header.Get("Content-Type")
		mt, params, _ := mime.ParseMediaType(ct)

		switch {
		case isBinaryMediaType(mt):
			// Leave the body completely untouched so the proxy can forward it.

		case mt == "multipart/form-data":
			// Buffer body, inspect only text parts, then restore for the proxy.
			buf, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
			body = extractMultipartText(buf, params["boundary"])

		default:
			buf, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
			// Reconstruct: buf already read + whatever remains in the original stream.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
			body = string(buf)
		}
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

// isBinaryMediaType returns true for media types whose body content is binary
// and should not be inspected by text-based WAF rules.
func isBinaryMediaType(mt string) bool {
	mt = strings.ToLower(mt)
	switch {
	case strings.HasPrefix(mt, "image/"),
		strings.HasPrefix(mt, "audio/"),
		strings.HasPrefix(mt, "video/"),
		strings.HasPrefix(mt, "application/vnd."):
		return true
	}
	switch mt {
	case "application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/x-zip-compressed",
		"application/x-tar",
		"application/gzip",
		"application/x-gzip",
		"application/x-7z-compressed",
		"application/x-rar-compressed":
		return true
	}
	return false
}

// extractMultipartText parses a multipart/form-data body and returns only the
// values of text (non-file) fields joined by newlines, suitable for WAF
// inspection. File upload parts are skipped entirely.
func extractMultipartText(data []byte, boundary string) string {
	if boundary == "" {
		return ""
	}
	mr := multipart.NewReader(bytes.NewReader(data), boundary)
	var sb strings.Builder
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		// Skip file upload parts.
		if part.FileName() != "" || isBinaryMediaType(part.Header.Get("Content-Type")) {
			part.Close()
			continue
		}
		val, _ := io.ReadAll(io.LimitReader(part, 4096))
		sb.Write(val)
		sb.WriteByte('\n')
		part.Close()
	}
	return sb.String()
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
