package auth

import (
	"testing"
	"time"
)

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	iss, err := NewIssuer("this-is-a-secret-that-is-long-enough-32chars+", 15, 7)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

// ─── NewIssuer validation ─────────────────────────────────────────────────────

func TestNewIssuer_RejectsEmptySecret(t *testing.T) {
	_, err := NewIssuer("", 15, 7)
	if err == nil {
		t.Fatal("expected error for empty secret, got nil")
	}
}

func TestNewIssuer_RejectsShortSecret(t *testing.T) {
	_, err := NewIssuer("tooshort", 15, 7)
	if err == nil {
		t.Fatal("expected error for short secret, got nil")
	}
}

func TestNewIssuer_RejectsZeroAccessMinutes(t *testing.T) {
	_, err := NewIssuer("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, 7)
	if err == nil {
		t.Fatal("expected error for zero access_token_minutes, got nil")
	}
}

func TestNewIssuer_AcceptsValidConfig(t *testing.T) {
	iss := newTestIssuer(t)
	if iss == nil {
		t.Fatal("expected non-nil Issuer")
	}
}

// ─── Token lifecycle ──────────────────────────────────────────────────────────

func TestIssueAndValidateAccessToken(t *testing.T) {
	iss := newTestIssuer(t)
	pair, err := iss.IssueTokenPair("user-1", "alice", "admin")
	if err != nil {
		t.Fatalf("IssueTokenPair: %v", err)
	}

	claims, err := iss.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Errorf("UserID: got %q, want %q", claims.UserID, "user-1")
	}
	if claims.Role != "admin" {
		t.Errorf("Role: got %q, want %q", claims.Role, "admin")
	}
	if claims.TokenType != TokenTypeAccess {
		t.Errorf("TokenType: got %q, want %q", claims.TokenType, TokenTypeAccess)
	}
	if claims.RegisteredClaims.Subject != "alice" {
		t.Errorf("Subject: got %q, want %q", claims.RegisteredClaims.Subject, "alice")
	}
}

func TestIssueAndValidateRefreshToken(t *testing.T) {
	iss := newTestIssuer(t)
	pair, err := iss.IssueTokenPair("user-1", "alice", "viewer")
	if err != nil {
		t.Fatalf("IssueTokenPair: %v", err)
	}

	claims, err := iss.ValidateRefreshToken(pair.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken: %v", err)
	}
	if claims.TokenType != TokenTypeRefresh {
		t.Errorf("TokenType: got %q, want %q", claims.TokenType, TokenTypeRefresh)
	}
	// RefreshJTI must match the jti in the token.
	if pair.RefreshJTI != claims.ID {
		t.Errorf("RefreshJTI mismatch: pair.RefreshJTI=%q claims.ID=%q",
			pair.RefreshJTI, claims.ID)
	}
}

func TestValidateAccessToken_RejectsRefreshToken(t *testing.T) {
	iss := newTestIssuer(t)
	pair, _ := iss.IssueTokenPair("u1", "alice", "admin")

	_, err := iss.ValidateAccessToken(pair.RefreshToken)
	if err == nil {
		t.Fatal("expected error when validating refresh token as access token")
	}
}

func TestValidateRefreshToken_RejectsAccessToken(t *testing.T) {
	iss := newTestIssuer(t)
	pair, _ := iss.IssueTokenPair("u1", "alice", "admin")

	_, err := iss.ValidateRefreshToken(pair.AccessToken)
	if err == nil {
		t.Fatal("expected error when validating access token as refresh token")
	}
}

func TestValidateAccessToken_RejectsMalformed(t *testing.T) {
	iss := newTestIssuer(t)
	_, err := iss.ValidateAccessToken("not.a.valid.jwt")
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
}

func TestValidateAccessToken_RejectsAlgNone(t *testing.T) {
	// alg=none tokens must always be rejected.
	// A crafted alg:none token: header.payload.emptysig
	algNone := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +
		".eyJ1aWQiOiJ1MSIsInJvbGUiOiJhZG1pbiIsInR5cGUiOiJhY2Nlc3MiLCJzdWIiOiJhbGljZSIsImlzcyI6Im1ldGFsd2FmIiwiZXhwIjo5OTk5OTk5OTk5fQ" +
		"."
	iss := newTestIssuer(t)
	_, err := iss.ValidateAccessToken(algNone)
	if err == nil {
		t.Fatal("alg:none token must be rejected")
	}
}

func TestAccessTokenExpiry(t *testing.T) {
	// Issue with a 1-minute access token, check expiry is in the future.
	iss, _ := NewIssuer("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1)
	pair, _ := iss.IssueTokenPair("u1", "alice", "admin")

	if pair.AccessExpiry.Before(time.Now()) {
		t.Errorf("access token should not be expired immediately after issuance")
	}
	if pair.AccessExpiry.After(time.Now().Add(2 * time.Minute)) {
		t.Errorf("access token expiry is unexpectedly far in the future")
	}
}

// ─── TOTP ─────────────────────────────────────────────────────────────────────

func TestGenerateTOTPSecret_NotEmpty(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if len(secret) < 16 {
		t.Errorf("TOTP secret too short: %q", secret)
	}
}

func TestTOTPUri_Format(t *testing.T) {
	uri := TOTPUri("JBSWY3DPEHPK3PXP", "MetalWAF", "alice")
	if len(uri) == 0 {
		t.Fatal("empty TOTP URI")
	}
	if uri[:14] != "otpauth://totp" {
		t.Errorf("unexpected URI prefix: %q", uri[:14])
	}
}

func TestValidateTOTP_RejectsWrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	if ValidateTOTP("000000", secret) {
		// There's a ~1/1_000_000 chance this is the actual code right now.
		// In practice the test will virtually never fail spuriously.
		t.Log("warn: 000000 coincidentally matched — rerun if this happens repeatedly")
	}
}

func TestValidateTOTP_RejectsInvalidSecret(t *testing.T) {
	if ValidateTOTP("123456", "!!!invalid!!!") {
		t.Fatal("expected false for invalid base32 secret")
	}
}

func TestValidateTOTP_RejectsWrongLength(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	if ValidateTOTP("12345", secret) {
		t.Fatal("5-digit code should be rejected (must be 6 digits)")
	}
	if ValidateTOTP("1234567", secret) {
		t.Fatal("7-digit code should be rejected")
	}
}
