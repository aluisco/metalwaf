// Package license handles MetalWAF edition detection and license validation.
// The LITE edition is free and requires no license key.
// The PRO edition requires a valid license key that is validated against the
// MetalWAF license server (online, with a local encrypted cache for grace periods).
package license

import "time"

const (
	// gracePeriod is the maximum time the system will operate in PRO mode
	// without a successful online validation (e.g., during network outages).
	gracePeriod = 7 * 24 * time.Hour

	// cacheRefreshAfter is how long a cached validation token is considered fresh.
	cacheRefreshAfter = 24 * time.Hour

	// requestTimeout is the maximum time allowed for a license server HTTP call.
	requestTimeout = 10 * time.Second

	// maxResponseBytes limits the license server response to prevent abuse.
	maxResponseBytes = 8192

	// defaultLicenseServer is the base URL for license validation.
	defaultLicenseServer = "https://license.metalwaf.io"
)

// Tier represents the feature tier unlocked by a license.
type Tier string

const (
	TierLite Tier = "lite"
	TierPro  Tier = "pro"
)

// License holds the validated and decoded license details. It is the single
// source of truth for which features are available at runtime.
type License struct {
	ID           string
	CustomerName string
	Tier         Tier
	MaxSites     int // 0 = unlimited
	IssuedAt     time.Time
	ExpiresAt    *time.Time // nil = perpetual subscription
	LastChecked  time.Time  // time of last successful ONLINE validation
	Offline      bool       // true = validated from local cache, not from server
}

// Edition returns the string name of the active edition: "lite" or "pro".
func (l *License) Edition() string { return string(l.Tier) }

// IsPro returns true when the license grants access to PRO features.
func (l *License) IsPro() bool { return l.Tier == TierPro }

// IsExpired returns true when the license subscription has lapsed.
func (l *License) IsExpired() bool {
	if l.ExpiresAt == nil {
		return false
	}
	return time.Now().UTC().After(*l.ExpiresAt)
}

// GracePeriodExpired returns true when the last successful online check is
// older than gracePeriod. When this happens the system must fall back to LITE.
func (l *License) GracePeriodExpired() bool {
	if l.LastChecked.IsZero() {
		return true
	}
	return time.Since(l.LastChecked) > gracePeriod
}

// DaysUntilGraceExpiry returns how many full days remain in the offline grace
// period before the system would revert to LITE.
func (l *License) DaysUntilGraceExpiry() int {
	if l.LastChecked.IsZero() {
		return 0
	}
	remaining := gracePeriod - time.Since(l.LastChecked)
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Hours() / 24)
}

// liteOnly returns a License for the free LITE edition.
func liteOnly() *License {
	return &License{
		Tier:        TierLite,
		LastChecked: time.Now().UTC(),
	}
}
