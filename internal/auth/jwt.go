// Package auth implements JWT-based authentication for MetalWAF.
// Access tokens (short-lived, 15 min default) and refresh tokens (long-lived,
// 7 days default) are issued together at login. Refresh tokens are stored in
// the sessions table so they can be revoked on logout.
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// TokenTypeAccess identifies short-lived access tokens.
	TokenTypeAccess = "access"
	// TokenTypeRefresh identifies long-lived refresh tokens.
	TokenTypeRefresh = "refresh"

	issuerName = "metalwaf"

	// MinSecretLen enforces a minimum entropy floor for JWT secrets.
	MinSecretLen = 32
)

// Claims is the custom JWT payload carried in every MetalWAF token.
type Claims struct {
	UserID    string `json:"uid"`
	Role      string `json:"role"`
	TokenType string `json:"type"`
	jwt.RegisteredClaims
}

// TokenPair holds the two tokens issued together at login / refresh.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	AccessExpiry time.Time `json:"expires_at"`
	// RefreshJTI is the UUID stored in the DB as the session's refresh_token.
	// It is the jti of the refresh JWT and is NOT exposed to clients directly.
	RefreshJTI string `json:"-"`
}

// Issuer handles JWT creation and validation.
// Create one with NewIssuer and keep it for the lifetime of the application.
type Issuer struct {
	secret          []byte
	accessDuration  time.Duration
	refreshDuration time.Duration
}

// NewIssuer creates an Issuer. secret must be at least 32 characters.
// Generate a strong secret with: openssl rand -hex 32
func NewIssuer(secret string, accessMinutes, refreshDays int) (*Issuer, error) {
	if secret == "" {
		return nil, errors.New("auth: jwt_secret is required — set METALWAF_JWT_SECRET or auth.jwt_secret in config")
	}
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf(
			"auth: jwt_secret is too short (%d chars); minimum is %d — use: openssl rand -hex 32",
			len(secret), MinSecretLen,
		)
	}
	if accessMinutes <= 0 {
		return nil, fmt.Errorf("auth: access_token_minutes must be > 0, got %d", accessMinutes)
	}
	if refreshDays <= 0 {
		return nil, fmt.Errorf("auth: refresh_token_days must be > 0, got %d", refreshDays)
	}
	return &Issuer{
		secret:          []byte(secret),
		accessDuration:  time.Duration(accessMinutes) * time.Minute,
		refreshDuration: time.Duration(refreshDays) * 24 * time.Hour,
	}, nil
}

// RefreshDuration exposes the refresh token lifetime (needed to compute session expiry).
func (iss *Issuer) RefreshDuration() time.Duration { return iss.refreshDuration }

// IssueTokenPair creates a new (access, refresh) token pair for a user.
// The refresh token's JTI (UUID) must be stored in the sessions table by the caller.
func (iss *Issuer) IssueTokenPair(userID, username, role string) (*TokenPair, error) {
	now := time.Now().UTC()
	accessExpiry := now.Add(iss.accessDuration)

	// ── Access token ───────────────────────────────────────────────────────
	accessClaims := Claims{
		UserID:    userID,
		Role:      role,
		TokenType: TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   username,
			Issuer:    issuerName,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
		},
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).
		SignedString(iss.secret)
	if err != nil {
		return nil, fmt.Errorf("auth: signing access token: %w", err)
	}

	// ── Refresh token ──────────────────────────────────────────────────────
	// We store the JTI (UUID) in the DB sessions table, not the full JWT.
	// This means a DB leak alone cannot be used to issue refresh requests —
	// the attacker would still need the JWT secret to validate the JWT.
	refreshJTI := uuid.NewString()
	refreshClaims := Claims{
		UserID:    userID,
		Role:      role,
		TokenType: TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refreshJTI,
			Subject:   username,
			Issuer:    issuerName,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(iss.refreshDuration)),
		},
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).
		SignedString(iss.secret)
	if err != nil {
		return nil, fmt.Errorf("auth: signing refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessExpiry: accessExpiry,
		RefreshJTI:   refreshJTI,
	}, nil
}

// ValidateAccessToken parses and validates an access token.
func (iss *Issuer) ValidateAccessToken(raw string) (*Claims, error) {
	return iss.parseToken(raw, TokenTypeAccess)
}

// ValidateRefreshToken parses and validates a refresh token.
func (iss *Issuer) ValidateRefreshToken(raw string) (*Claims, error) {
	return iss.parseToken(raw, TokenTypeRefresh)
}

func (iss *Issuer) parseToken(raw, expectedType string) (*Claims, error) {
	tok, err := jwt.ParseWithClaims(raw, &Claims{},
		func(t *jwt.Token) (interface{}, error) {
			// Algorithm confusion prevention: reject any non-HMAC algorithm.
			// This blocks alg:none attacks and RS256/ES256 confusion.
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("auth: unexpected signing method %q — only HS256 is accepted",
					t.Header["alg"])
			}
			return iss.secret, nil
		},
		jwt.WithValidMethods([]string{"HS256"}), // belt-and-suspenders
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	claims, ok := tok.Claims.(*Claims)
	if !ok || !tok.Valid {
		return nil, errors.New("auth: invalid token claims")
	}
	if claims.TokenType != expectedType {
		return nil, fmt.Errorf("auth: wrong token type: got %q, want %q",
			claims.TokenType, expectedType)
	}
	return claims, nil
}
