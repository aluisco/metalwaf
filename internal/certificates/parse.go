package certificates

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// CertInfo carries the metadata extracted from a parsed certificate leaf.
type CertInfo struct {
	// Domains contains the Subject CN and all DNS SANs in the certificate.
	Domains []string
	// ExpiresAt is the NotAfter time of the leaf certificate.
	ExpiresAt time.Time
}

// ParsePair parses and validates a PEM-encoded certificate and private key.
// It:
//   - Verifies the key matches the certificate (X509KeyPair).
//   - Rejects expired certificates.
//   - Extracts the domain names (CN + SANs).
//
// Returns the parsed tls.Certificate with Leaf pre-populated, plus metadata.
func ParsePair(certPEM, keyPEM []byte) (*tls.Certificate, *CertInfo, error) {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("certificates: invalid cert/key pair: %w", err)
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, nil, errors.New("certificates: empty certificate chain")
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("certificates: parsing leaf: %w", err)
	}
	// Pre-set leaf so the runtime doesn't have to re-parse on every handshake.
	tlsCert.Leaf = leaf

	if time.Now().After(leaf.NotAfter) {
		return nil, nil, fmt.Errorf("certificates: certificate expired on %s",
			leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	// Belt-and-suspenders: verify public key match in case the user supplied
	// a mismatched pair that tls.X509KeyPair somehow accepted.
	if err := verifyKeyMatch(leaf, &tlsCert); err != nil {
		return nil, nil, fmt.Errorf("certificates: key mismatch: %w", err)
	}

	domains := extractDomains(leaf)
	if len(domains) == 0 {
		return nil, nil, errors.New("certificates: no domain names in certificate — add a SAN or set the Subject CN")
	}

	return &tlsCert, &CertInfo{Domains: domains, ExpiresAt: leaf.NotAfter}, nil
}

// FirstDomain parses only the certificate PEM and returns the primary domain
// (first SAN, or CN if no SANs). Used when only the cert is available
// (e.g. to display domain in the dashboard without decrypting the key).
func FirstDomain(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	domains := extractDomains(leaf)
	if len(domains) == 0 {
		return ""
	}
	return domains[0]
}

// extractDomains returns all domain names in a certificate (SANs + CN).
// SANs take precedence; CN is appended only if not already listed.
func extractDomains(leaf *x509.Certificate) []string {
	domains := append([]string{}, leaf.DNSNames...)
	if leaf.Subject.CommonName != "" {
		for _, d := range domains {
			if d == leaf.Subject.CommonName {
				return domains // CN already in SANs
			}
		}
		domains = append([]string{leaf.Subject.CommonName}, domains...)
	}
	return domains
}

// verifyKeyMatch checks that the public key in the leaf certificate matches the
// private key loaded in the tls.Certificate. tls.X509KeyPair already does this,
// but we re-verify as a defense against future API changes.
func verifyKeyMatch(leaf *x509.Certificate, tc *tls.Certificate) error {
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		priv, ok := tc.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("leaf uses ECDSA but private key is not ECDSA")
		}
		if pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
			return errors.New("ECDSA public key does not match private key")
		}
	case *rsa.PublicKey:
		priv, ok := tc.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("leaf uses RSA but private key is not RSA")
		}
		if pub.N.Cmp(priv.PublicKey.N) != 0 {
			return errors.New("RSA public key does not match private key")
		}
		// ed25519 and other types: trust tls.X509KeyPair's verification above.
	}
	return nil
}
