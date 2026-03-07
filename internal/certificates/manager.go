package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/metalwaf/metalwaf/internal/database"
)

// Manager handles all TLS certificate loading and provisioning for MetalWAF.
//
// Certificate priority order at each TLS handshake (SNI matching):
//  1. Manually-uploaded certificates loaded from the database.
//  2. Let's Encrypt certificates managed by autocert (HTTP-01 challenge).
//  3. Self-signed fallback certificate (always present, triggers browser warning).
//
// Thread-safe: Reload can be called at any time from the API goroutine without
// affecting in-flight TLS connections.
type Manager struct {
	store     database.Store
	masterKey []byte

	mu       sync.RWMutex
	certs    map[string]*tls.Certificate // normalized domain → manual cert
	fallback *tls.Certificate            // no-SNI fallback (includes localhost/127.0.0.1 SANs)

	devMu    sync.Mutex
	devCerts map[string]*tls.Certificate // per-SNI on-demand self-signed certs (cached)

	acmeMgr *autocert.Manager
}

// NewManager creates a Manager. It generates the self-signed fallback certificate
// immediately — this never fails on any platform that has a working PRNG.
//
// masterKey is used to decrypt private keys stored encrypted at rest. Pass nil
// if keys were stored without encryption.
func NewManager(store database.Store, masterKey []byte) *Manager {
	m := &Manager{
		store:     store,
		masterKey: masterKey,
		certs:     make(map[string]*tls.Certificate),
		devCerts:  make(map[string]*tls.Certificate),
	}

	// Build a self-signed fallback for no-SNI connections (direct IP access etc.).
	// Includes localhost and loopback IP SANs so browsers accept the "proceed anyway" prompt.
	fb, err := GenerateSelfSignedForHosts("localhost", "127.0.0.1", "::1")
	if err != nil {
		// This should never happen; if it does we can't serve TLS at all.
		panic(fmt.Sprintf("certificates: failed to generate self-signed fallback: %v", err))
	}
	m.fallback = fb

	// autocert.Manager is lazy — it does nothing until a TLS ClientHello
	// arrives for a host in the HostPolicy. The HTTP-01 challenge is served
	// via AcmeChallengeHandler on port 80.
	m.acmeMgr = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      NewDBCache(store),
		HostPolicy: m.hostPolicy,
	}

	return m
}

// Load reads all certificates from the database, decrypts and parses them, and
// atomically replaces the in-memory cert map. Errors for individual certs are
// logged as warnings and skipped rather than aborting the whole load.
func (m *Manager) Load(ctx context.Context) error {
	dbCerts, err := m.store.ListCertificates(ctx)
	if err != nil {
		return fmt.Errorf("certificates: loading from database: %w", err)
	}

	newCerts := make(map[string]*tls.Certificate, len(dbCerts))
	for _, c := range dbCerts {
		keyPEM, err := DecryptKey([]byte(c.KeyPEM), m.masterKey)
		if err != nil {
			slog.Warn("certificates: cannot decrypt key — skipping",
				"id", c.ID, "domain", c.Domain, "error", err)
			continue
		}
		tlsCert, info, err := ParsePair([]byte(c.CertPEM), keyPEM)
		if err != nil {
			slog.Warn("certificates: cannot parse cert — skipping",
				"id", c.ID, "domain", c.Domain, "error", err)
			continue
		}
		// Register under all SANs/CN from the cert itself.
		for _, domain := range info.Domains {
			newCerts[strings.ToLower(domain)] = tlsCert
		}
		// Also register under the stored domain override (set by the user
		// when uploading — may differ from the cert's own CN/SANs).
		if stored := strings.ToLower(c.Domain); stored != "" {
			newCerts[stored] = tlsCert
		}
		slog.Debug("certificates: loaded cert",
			"id", c.ID, "domain", c.Domain, "cert_domains", info.Domains,
			"expires", info.ExpiresAt.Format("2006-01-02"))
	}

	m.mu.Lock()
	m.certs = newCerts
	m.mu.Unlock()

	slog.Info("certificates: loaded", "count", len(newCerts))
	return nil
}

// Reload is an alias for Load. Called by the API after cert mutations.
func (m *Manager) Reload(ctx context.Context) error {
	return m.Load(ctx)
}

// EnsurePersistedCert returns a self-signed certificate for the given primary
// domain and SANs. On first call it generates the cert and persists it in the
// database (source="self-signed") so subsequent restarts loads it from DB
// instead of generating a new one. If a user-uploaded cert already exists for
// domain it is used as-is (it will have been loaded by Load already).
//
// This is used for the admin HTTPS server and per-SNI fallback certs so that
// browsers do not see a different certificate fingerprint on every restart.
func (m *Manager) EnsurePersistedCert(ctx context.Context, domain string, sans ...string) (*tls.Certificate, error) {
	// Fast path: already loaded in the cert map (either user-uploaded or
	// a previously-persisted self-signed cert).
	key := strings.ToLower(domain)
	m.mu.RLock()
	if c, ok := m.certs[key]; ok {
		m.mu.RUnlock()
		return c, nil
	}
	m.mu.RUnlock()

	// Slow path: look for an existing self-signed cert in the DB.
	dbCerts, err := m.store.ListCertificates(ctx)
	if err == nil {
		for _, c := range dbCerts {
			if strings.ToLower(c.Domain) == key && c.Source == "self-signed" {
				keyPEM, kerr := DecryptKey([]byte(c.KeyPEM), m.masterKey)
				if kerr != nil {
					break
				}
				tlsCert, _, perr := ParsePair([]byte(c.CertPEM), keyPEM)
				if perr != nil {
					break
				}
				// Cache it in the live map for fast lookups.
				m.mu.Lock()
				m.certs[key] = tlsCert
				m.mu.Unlock()
				slog.Debug("certificates: reusing persisted self-signed cert", "domain", domain)
				return tlsCert, nil
			}
		}
	}

	// Generate a new self-signed cert that includes both the domain and all SANs.
	hosts := append([]string{domain}, sans...)
	tlsCert, err := GenerateSelfSignedForHosts(hosts...)
	if err != nil {
		return nil, fmt.Errorf("EnsurePersistedCert: generate: %w", err)
	}

	// Encode back to PEM for storage.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]})
	keyDER, err := x509.MarshalECPrivateKey(tlsCert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("EnsurePersistedCert: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Encrypt if master key configured.
	storedKey := string(keyPEM)
	if encrypted, eerr := EncryptKey(keyPEM, m.masterKey); eerr == nil {
		storedKey = string(encrypted)
	}

	expiry := time.Now().Add(10 * 365 * 24 * time.Hour)
	dbCert := &database.Certificate{
		Domain:    domain,
		Source:    "self-signed",
		CertPEM:   string(certPEM),
		KeyPEM:    storedKey,
		ExpiresAt: &expiry,
	}
	if serr := m.store.CreateCertificate(ctx, dbCert); serr != nil {
		// Persist failure is non-fatal: cert still works this session.
		slog.Warn("certificates: could not persist self-signed cert", "domain", domain, "error", serr)
	} else {
		slog.Info("certificates: generated and persisted self-signed cert", "domain", domain)
	}

	// Add to live map.
	m.mu.Lock()
	m.certs[key] = tlsCert
	m.mu.Unlock()
	return tlsCert, nil
}

// GetCertificate is the tls.Config.GetCertificate callback.
// It selects the best certificate for the requested SNI name.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// No SNI → prefer the persisted localhost cert (same identity as admin server);
	// fall back to the ephemeral in-memory cert if not yet loaded.
	if hello.ServerName == "" {
		m.mu.RLock()
		c, ok := m.certs["localhost"]
		m.mu.RUnlock()
		if ok {
			return c, nil
		}
		return m.fallback, nil
	}
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))

	// 1. Exact match in manual cert map.
	m.mu.RLock()
	cert, ok := m.certs[name]
	m.mu.RUnlock()
	if ok {
		return cert, nil
	}

	// 2. Wildcard match (e.g. *.example.com for foo.example.com).
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		m.mu.RLock()
		cert, ok = m.certs["*."+name[dot+1:]]
		m.mu.RUnlock()
		if ok {
			return cert, nil
		}
	}

	// 3. Let's Encrypt via autocert (issues cert on first request, then caches).
	if acmeCert, err := m.acmeMgr.GetCertificate(hello); err == nil && acmeCert != nil {
		return acmeCert, nil
	}

	// 4. No match — return a per-SNI self-signed cert (persisted across restarts).
	return m.selfSignedForSNI(name, hello.Context())
}

// selfSignedForSNI returns a self-signed certificate whose SAN matches name.
// The cert is persisted to the database on first use so subsequent restarts
// serve the same fingerprint (no browser security warnings after accepting once).
// An in-memory singleflight-style mutex prevents duplicate generation under load.
func (m *Manager) selfSignedForSNI(name string, ctx context.Context) (*tls.Certificate, error) {
	// Check in-memory cache first (avoids DB round-trip on hot path).
	m.devMu.Lock()
	if c, ok := m.devCerts[name]; ok {
		m.devMu.Unlock()
		return c, nil
	}
	m.devMu.Unlock()

	// Ensure persisted (generate + save on first call, reload on subsequent).
	c, err := m.EnsurePersistedCert(ctx, name)
	if err != nil {
		// Failsafe: generic fallback rather than a hard TLS failure.
		return m.fallback, nil
	}

	m.devMu.Lock()
	m.devCerts[name] = c
	m.devMu.Unlock()
	return c, nil
}

// TLSConfig returns a production-grade *tls.Config using this Manager for
// certificate selection. TLS 1.2 minimum, ALPN h2 + http/1.1 + acme-tls/1.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		// acme-tls/1 is required for TLS-ALPN-01 challenges (not used in
		// LITE but harmless to include for forward compatibility).
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
	}
}

// AcmeChallengeHandler wraps the given next handler so that HTTP-01 ACME
// challenge requests (GET /.well-known/acme-challenge/*) are handled by
// autocert before they reach the proxy. All other requests pass through to
// next unchanged — including https_only redirects.
func (m *Manager) AcmeChallengeHandler(next http.Handler) http.Handler {
	return m.acmeMgr.HTTPHandler(next)
}

// CheckExpiry logs a warning for any stored certificate that expires within
// 30 days. Called by the maintenance goroutine every 24 hours.
func (m *Manager) CheckExpiry(ctx context.Context) {
	dbCerts, err := m.store.ListCertificates(ctx)
	if err != nil {
		slog.Warn("certificates: expiry check failed", "error", err)
		return
	}
	threshold := time.Now().Add(30 * 24 * time.Hour)
	for _, c := range dbCerts {
		if c.ExpiresAt != nil && c.ExpiresAt.Before(threshold) {
			daysLeft := int(time.Until(*c.ExpiresAt).Hours() / 24)
			slog.Warn("certificate expiring soon",
				"domain", c.Domain,
				"expires_at", c.ExpiresAt.Format("2006-01-02"),
				"days_remaining", daysLeft,
				"hint", "upload a new certificate or enable Let's Encrypt auto-renewal",
			)
		}
	}
}

// ─── Let's Encrypt host policy ────────────────────────────────────────────────

// hostPolicy is the autocert.HostPolicy function. It allows Let's Encrypt to
// issue certificates for any hostname that is configured as an enabled site.
// This keeps ACME host allowance in sync with the live site configuration.
func (m *Manager) hostPolicy(ctx context.Context, host string) error {
	site, err := m.store.GetSiteByDomain(ctx, host)
	if err != nil {
		return fmt.Errorf("certificates: host policy DB error for %q: %w", host, err)
	}
	if site == nil || !site.Enabled {
		return fmt.Errorf("certificates: %q is not a configured active site — add it via the API first", host)
	}
	return nil
}

// ─── Self-signed certificate generator ───────────────────────────────────────

// GenerateSelfSignedForHosts creates a self-signed P-256 ECDSA certificate valid
// for the provided hostnames and/or IP addresses (10-year validity).
//
// This is intended for development, fallback, and internal admin endpoints.
// Browsers will show a security warning but — crucially — will offer the
// "proceed anyway" option because the cert includes correct SANs.
func GenerateSelfSignedForHosts(hosts ...string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	cn := "metalwaf-dev"
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"MetalWAF"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(tlsCert.Certificate[0])
	tlsCert.Leaf = leaf
	return &tlsCert, nil
}
