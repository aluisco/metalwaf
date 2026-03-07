package api

import "net/http"

type infoHandler struct {
	httpAddr  string
	httpsAddr string
}

// Get handles GET /api/v1/info.
// Returns the proxy listen addresses so the UI can show port information.
func (h *infoHandler) Get(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]string{
		"http_addr":  h.httpAddr,
		"https_addr": h.httpsAddr,
	})
}
