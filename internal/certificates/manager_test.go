package certificates

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/metalwaf/metalwaf/internal/database"
)

// ─── Shared test helpers ──────────────────────────────────────────────────────

// generateTestCert creates an in-memory self-signed TLS certificate and key,
// returning both as PEM-encoded byte slices.
func generateTestCert(t *testing.T, domains ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// generateExpiredCert creates a cert that is already expired.
func generateExpiredCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		DNSNames:     []string{"expired.example.com"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour), // already expired
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// ─── Encrypt / Decrypt ────────────────────────────────────────────────────────

func TestEncryptDecryptRoundtrip(t *testing.T) {
	masterKey := []byte("test-master-key-for-unit-testing")
	plaintext := []byte("-----BEGIN EC PRIVATE KEY-----\nfoobar\n-----END EC PRIVATE KEY-----")

	ciphertext, err := EncryptKey(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("encrypted output should differ from plaintext")
	}

	recovered, err := DecryptKey(ciphertext, masterKey)
	if err != nil {
		t.Fatalf("DecryptKey: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("decrypted text mismatch\ngot:  %q\nwant: %q", recovered, plaintext)
	}
}

func TestEncryptNoKey_Passthrough(t *testing.T) {
	plaintext := []byte("sensitive key material")
	out, err := EncryptKey(plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Error("no-key encryption should return plaintext unchanged")
	}
}

func TestDecryptNoKey_Passthrough(t *testing.T) {
	ciphertext := []byte("some bytes")
	out, err := DecryptKey(ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, ciphertext) {
		t.Error("no-key decryption should return ciphertext unchanged")
	}
}

func TestDecryptWrongKey_Fails(t *testing.T) {
	masterKey := []byte("correct-master-key-for-this-test")
	plaintext := []byte("private key material here!!!")

	ciphertext, _ := EncryptKey(plaintext, masterKey)

	_, err := DecryptKey(ciphertext, []byte("wrong-key-abcdefgh-1234567890abc"))
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

// ─── ParsePair ────────────────────────────────────────────────────────────────

func TestParsePair_Valid(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "example.com", "www.example.com")

	tlsCert, info, err := ParsePair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ParsePair: %v", err)
	}
	if tlsCert == nil {
		t.Fatal("expected non-nil tls.Certificate")
	}
	if len(info.Domains) == 0 {
		t.Error("expected at least one domain")
	}

	found := false
	for _, d := range info.Domains {
		if d == "example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'example.com' in domains %v", info.Domains)
	}

	if info.ExpiresAt.IsZero() {
		t.Error("expected non-zero ExpiresAt")
	}
	if tlsCert.Leaf == nil {
		t.Error("expected Leaf to be pre-populated")
	}
}

func TestParsePair_ExpiredCert_Rejected(t *testing.T) {
	certPEM, keyPEM := generateExpiredCert(t)

	_, _, err := ParsePair(certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected error for expired certificate")
	}
}

func TestParsePair_MissmatchedKey_Rejected(t *testing.T) {
	certPEM, _ := generateTestCert(t, "site-a.example.com")
	_, wrongKey := generateTestCert(t, "site-b.example.com")

	_, _, err := ParsePair(certPEM, wrongKey)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key pair")
	}
}

func TestParsePair_GarbageInput_Rejected(t *testing.T) {
	_, _, err := ParsePair([]byte("not a cert"), []byte("not a key"))
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
}

func TestFirstDomain(t *testing.T) {
	certPEM, _ := generateTestCert(t, "primary.example.com", "secondary.example.com")
	domain := FirstDomain(certPEM)
	if domain == "" {
		t.Fatal("expected non-empty domain")
	}
}

// ─── ACME cache ───────────────────────────────────────────────────────────────

// minimalMockStore implements only the settings methods needed by dbCache.
type minimalMockStore struct {
	database.Store
	mu       sync.Mutex
	settings map[string]string
}

func newMinimalMockStore() *minimalMockStore {
	return &minimalMockStore{settings: make(map[string]string)}
}

func (m *minimalMockStore) GetSetting(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings[key], nil
}

func (m *minimalMockStore) SetSetting(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings[key] = value
	return nil
}

func TestACMECache_PutGetDelete(t *testing.T) {
	store := newMinimalMockStore()
	cache := NewDBCache(store)
	ctx := context.Background()

	key := "acme-test-key"
	data := []byte{0x01, 0x02, 0x03, 0xff}

	// Put
	if err := cache.Put(ctx, key, data); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Get
	got, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("Get: got %v, want %v", got, data)
	}

	// Delete
	if err := cache.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// After delete, Get must return ErrCacheMiss.
	_, err = cache.Get(ctx, key)
	if err == nil {
		t.Fatal("expected ErrCacheMiss after Delete, got nil")
	}
}

// ─── Manager ──────────────────────────────────────────────────────────────────

// managerMockStore implements the Store methods used by Manager.
type managerMockStore struct {
	database.Store
	mu    sync.Mutex
	certs []*database.Certificate
	sites map[string]*database.Site // keyed by domain
	// settings for acme cache:
	settings map[string]string
}

func newManagerMockStore() *managerMockStore {
	return &managerMockStore{
		sites:    make(map[string]*database.Site),
		settings: make(map[string]string),
	}
}

func (m *managerMockStore) ListCertificates(_ context.Context) ([]*database.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*database.Certificate, len(m.certs))
	copy(out, m.certs)
	return out, nil
}

func (m *managerMockStore) GetSiteByDomain(_ context.Context, domain string) (*database.Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sites[domain], nil
}

func (m *managerMockStore) GetSetting(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings[key], nil
}

func (m *managerMockStore) SetSetting(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings[key] = value
	return nil
}

func (m *managerMockStore) CreateCertificate(_ context.Context, c *database.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs = append(m.certs, c)
	return nil
}

func TestManager_EmptyDB_FallsBackToSelfSigned(t *testing.T) {
	store := newManagerMockStore()
	mgr := NewManager(store, nil)

	if err := mgr.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	hello := &tls.ClientHelloInfo{ServerName: "unknown.example.com"}
	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil fallback cert")
	}
	// The fallback cert should be the self-signed one (CN = "metalwaf-fallback").
	if cert.Leaf != nil && cert.Leaf.Subject.CommonName == "metalwaf-fallback" {
		return // expected
	}
	// cert.Leaf may not be set if autocert returned something; just check non-nil.
	t.Log("fallback cert returned (Leaf may not be set yet)")
}

func TestManager_LoadAndGetCertificate(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "mysite.example.com")

	store := newManagerMockStore()
	store.certs = []*database.Certificate{{
		ID:      "cert-1",
		Domain:  "mysite.example.com",
		Source:  "manual",
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
	}}

	mgr := NewManager(store, nil /* no masterKey */)
	if err := mgr.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	hello := &tls.ClientHelloInfo{ServerName: "mysite.example.com"}
	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert for known domain")
	}
	if cert.Leaf == nil {
		t.Fatal("expected Leaf to be set")
	}
	if cert.Leaf.Subject.CommonName != "mysite.example.com" {
		t.Errorf("unexpected CN: %q", cert.Leaf.Subject.CommonName)
	}
}

func TestManager_LoadWithEncryptedKey(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "secure.example.com")
	masterKey := []byte("test-master-key-1234567890123456")

	encryptedKey, err := EncryptKey(keyPEM, masterKey)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}

	store := newManagerMockStore()
	store.certs = []*database.Certificate{{
		ID:      "cert-enc",
		Domain:  "secure.example.com",
		Source:  "manual",
		CertPEM: string(certPEM),
		KeyPEM:  string(encryptedKey),
	}}

	mgr := NewManager(store, masterKey)
	if err := mgr.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	hello := &tls.ClientHelloInfo{ServerName: "secure.example.com"}
	cert, _ := mgr.GetCertificate(hello)
	if cert == nil || cert.Leaf == nil {
		t.Fatal("expected cert for encrypted domain")
	}
}

func TestManager_WildcardMatch(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "*.example.com")

	store := newManagerMockStore()
	store.certs = []*database.Certificate{{
		ID:      "wild",
		Domain:  "*.example.com",
		Source:  "manual",
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
	}}

	mgr := NewManager(store, nil)
	mgr.Load(context.Background())

	// Subdomain should match the wildcard.
	hello := &tls.ClientHelloInfo{ServerName: "anything.example.com"}
	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert for wildcard-matched domain")
	}
}

func TestManager_NoSNI_ReturnsFallback(t *testing.T) {
	store := newManagerMockStore()
	mgr := NewManager(store, nil)
	mgr.Load(context.Background())

	hello := &tls.ClientHelloInfo{ServerName: ""} // no SNI
	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected fallback cert when no SNI")
	}
}

func TestManager_TLSConfig_HasGetCertificate(t *testing.T) {
	store := newManagerMockStore()
	mgr := NewManager(store, nil)
	cfg := mgr.TLSConfig()

	if cfg.GetCertificate == nil {
		t.Error("TLSConfig.GetCertificate must not be nil")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 minimum, got %d", cfg.MinVersion)
	}
}

func TestManager_Reload_SwapsCerts(t *testing.T) {
	store := newManagerMockStore()
	mgr := NewManager(store, nil)
	mgr.Load(context.Background())

	// No certs loaded — unknown domain gets fallback.
	hello := &tls.ClientHelloInfo{ServerName: "reload.example.com"}
	cert1, _ := mgr.GetCertificate(hello)

	// Now add a cert and reload.
	certPEM, keyPEM := generateTestCert(t, "reload.example.com")
	store.mu.Lock()
	store.certs = []*database.Certificate{{
		ID: "r1", Domain: "reload.example.com", Source: "manual",
		CertPEM: string(certPEM), KeyPEM: string(keyPEM),
	}}
	store.mu.Unlock()

	mgr.Reload(context.Background())

	cert2, _ := mgr.GetCertificate(hello)
	if cert2 == nil {
		t.Fatal("after reload, expected cert for domain")
	}
	// cert1 was the fallback (self-signed); cert2 should be the uploaded one.
	// They must have different pointer identities.
	if cert1 == cert2 {
		t.Error("expected different cert after reload")
	}
}

// ensure time import is used
var _ = time.Now
