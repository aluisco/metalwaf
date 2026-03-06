// Package api implements the MetalWAF REST API under /api/v1/.
// All responses use a consistent JSON envelope: {"data":...} or {"error":"..."}.
package api

import (
	"encoding/json"
	"io"
	"net/http"
)

// envelope is the standard JSON response wrapper for all API responses.
type envelope struct {
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// respond writes a successful JSON response with an optional data payload.
func respond(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(envelope{Data: data})
}

// respondError writes a JSON error response.
func respondError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(envelope{Error: msg})
}

// respondCreated is shorthand for respond with 201 Created.
func respondCreated(w http.ResponseWriter, data any) {
	respond(w, http.StatusCreated, data)
}

// decode reads and decodes a JSON request body with an enforced size limit.
// maxBytes prevents denial-of-service via oversized request bodies.
func decode(r *http.Request, dst any, maxBytes int64) error {
	if r.Body == nil {
		return io.EOF
	}
	return json.NewDecoder(io.LimitReader(r.Body, maxBytes)).Decode(dst)
}

// readBody reads the full request body up to maxBytes.
// Returns an error if the body is nil, unreadable, or exceeds the limit.
func readBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if r.Body == nil {
		return nil, io.EOF
	}
	return io.ReadAll(io.LimitReader(r.Body, maxBytes))
}
