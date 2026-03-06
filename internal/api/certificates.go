package api

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/metalwaf/metalwaf/internal/certificates"
	"github.com/metalwaf/metalwaf/internal/database"
)

// certsHandler handles all /api/v1/certificates routes.
type certsHandler struct {
	store     database.Store
	masterKey []byte
	reload    func(ctx context.Context) error
}

// certResponse is the API representation of a certificate.
// The private key is never returned to the client.
type certResponse struct {
	ID        string     `json:"id"`
	SiteID    string     `json:"site_id,omitempty"`
	Domain    string     `json:"domain"`
	Source    string     `json:"source"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	AutoRenew bool       `json:"auto_renew"`
	CreatedAt time.Time  `json:"created_at"`
}

func toCertResponse(c *database.Certificate) certResponse {
	return certResponse{
		ID:        c.ID,
		SiteID:    c.SiteID,
		Domain:    c.Domain,
		Source:    c.Source,
		ExpiresAt: c.ExpiresAt,
		AutoRenew: c.AutoRenew,
		CreatedAt: c.CreatedAt,
	}
}

// ─── List ─────────────────────────────────────────────────────────────────────

// List handles GET /api/v1/certificates.
func (h *certsHandler) List(w http.ResponseWriter, r *http.Request) {
	dbCerts, err := h.store.ListCertificates(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database error")
		return
	}
	out := make([]certResponse, 0, len(dbCerts))
	for _, c := range dbCerts {
		out = append(out, toCertResponse(c))
	}
	respond(w, http.StatusOK, out)
}

// ─── Get ──────────────────────────────────────────────────────────────────────

// Get handles GET /api/v1/certificates/{id}.
func (h *certsHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		respondError(w, http.StatusBadRequest, "invalid certificate id")
		return
	}
	c, err := h.store.GetCertificateByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database error")
		return
	}
	if c == nil {
		respondError(w, http.StatusNotFound, "certificate not found")
		return
	}
	respond(w, http.StatusOK, toCertResponse(c))
}

// ─── Create (manual upload) ───────────────────────────────────────────────────

type createCertRequest struct {
	SiteID    string `json:"site_id"`    // optional — global cert if empty
	CertPEM   string `json:"cert_pem"`   // required: PEM-encoded certificate (chain)
	KeyPEM    string `json:"key_pem"`    // required: PEM-encoded private key
	AutoRenew bool   `json:"auto_renew"` // enable Let's Encrypt auto-renewal
}

// Create handles POST /api/v1/certificates.
// Validates the cert/key pair, encrypts the private key at rest, stores in DB,
// and triggers a TLS manager reload so the cert is served immediately.
func (h *certsHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createCertRequest
	if err := decode(r, &req, 256*1024); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CertPEM == "" || req.KeyPEM == "" {
		respondError(w, http.StatusUnprocessableEntity, "cert_pem and key_pem are required")
		return
	}

	// Validate site reference if provided.
	if req.SiteID != "" {
		if _, err := uuid.Parse(req.SiteID); err != nil {
			respondError(w, http.StatusBadRequest, "invalid site_id")
			return
		}
		site, err := h.store.GetSiteByID(r.Context(), req.SiteID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "database error")
			return
		}
		if site == nil {
			respondError(w, http.StatusNotFound, "site not found")
			return
		}
	}

	// Parse and validate the cert+key pair.
	_, info, err := certificates.ParsePair([]byte(req.CertPEM), []byte(req.KeyPEM))
	if err != nil {
		respondError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	// Encrypt the private key before persisting.
	encryptedKey, err := certificates.EncryptKey([]byte(req.KeyPEM), h.masterKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to encrypt private key")
		return
	}

	expiresAt := info.ExpiresAt
	c := &database.Certificate{
		ID:        uuid.NewString(),
		SiteID:    req.SiteID,
		Domain:    info.Domains[0], // primary domain
		Source:    "manual",
		CertPEM:   req.CertPEM,
		KeyPEM:    string(encryptedKey),
		ExpiresAt: &expiresAt,
		AutoRenew: req.AutoRenew,
	}
	if err := h.store.CreateCertificate(r.Context(), c); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to store certificate")
		return
	}

	h.triggerReload(r)
	respondCreated(w, toCertResponse(c))
}

// ─── Delete ───────────────────────────────────────────────────────────────────

// Delete handles DELETE /api/v1/certificates/{id}.
func (h *certsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		respondError(w, http.StatusBadRequest, "invalid certificate id")
		return
	}

	existing, err := h.store.GetCertificateByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		respondError(w, http.StatusNotFound, "certificate not found")
		return
	}

	if err := h.store.DeleteCertificate(r.Context(), id); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete certificate")
		return
	}

	h.triggerReload(r)
	w.WriteHeader(http.StatusNoContent)
}

// ─── Let's Encrypt request ────────────────────────────────────────────────────

type letsEncryptRequest struct {
	Domain string `json:"domain"` // the domain to get a Let's Encrypt certificate for
}

// RequestACME handles POST /api/v1/certificates/letsencrypt.
// It validates that the domain is registered as an active site and returns 202
// Accepted. The actual certificate issuance happens lazily on the next HTTPS
// connection to that domain via autocert.
func (h *certsHandler) RequestACME(w http.ResponseWriter, r *http.Request) {
	var req letsEncryptRequest
	if err := decode(r, &req, 1024); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Domain == "" {
		respondError(w, http.StatusUnprocessableEntity, "domain is required")
		return
	}

	site, err := h.store.GetSiteByDomain(r.Context(), req.Domain)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database error")
		return
	}
	if site == nil || !site.Enabled {
		respondError(w, http.StatusNotFound,
			"domain is not configured as an active site — create the site first")
		return
	}

	// Issuance is lazy: autocert will issue the certificate on the next TLS
	// handshake for this domain, provided the HTTP-01 challenge is reachable.
	respond(w, http.StatusAccepted, map[string]string{
		"status":  "pending",
		"domain":  req.Domain,
		"message": "Certificate will be automatically issued by Let's Encrypt on the next HTTPS connection to this domain. Ensure port 80 is publicly reachable for the HTTP-01 challenge.",
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (h *certsHandler) triggerReload(r *http.Request) {
	if h.reload != nil {
		_ = h.reload(r.Context())
	}
}
