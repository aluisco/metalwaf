// Package database defines the domain models and the Store interface used by
// all MetalWAF editions. Concrete implementations live in sub-packages
// (sqlite, postgres).
package database

import (
	"context"
	"time"
)

// ─── Domain models ────────────────────────────────────────────────────────────

type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
	Role         string // admin | viewer
	TOTPSecret   string
	TOTPEnabled  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Session struct {
	ID           string
	UserID       string
	RefreshToken string
	ExpiresAt    time.Time
	IPAddress    string
	UserAgent    string
	CreatedAt    time.Time
}

type Site struct {
	ID             string
	Name           string
	Domain         string
	WAFMode        string // monitor | protect | off
	HTTPSOnly      bool
	Enabled        bool
	RateLimitRPS   float64 // 0 = inherit global
	RateLimitBurst int     // 0 = inherit global
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Upstream struct {
	ID        string
	SiteID    string
	URL       string
	Weight    int
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type WAFRule struct {
	ID          string
	SiteID      *string // nil = global rule
	Name        string
	Description string
	Field       string // header | body | uri | query | method | ip | user_agent
	Operator    string // contains | regex | equals | startswith | endswith | cidr
	Value       string
	Action      string // block | detect | allow
	Score       int
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type IPList struct {
	ID        string
	SiteID    *string // nil = global
	Type      string  // allow | block
	CIDR      string
	Comment   string
	CreatedAt time.Time
}

// CountEntry is a (label, count) pair returned by analytics aggregation queries.
type CountEntry struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

type Certificate struct {
	ID        string
	Domain    string
	Source    string // manual | letsencrypt
	CertPEM   string
	KeyPEM    string
	ExpiresAt *time.Time
	AutoRenew bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type RequestLog struct {
	ID          string
	SiteID      *string
	Timestamp   time.Time
	ClientIP    string
	Method      string
	Host        string
	Path        string
	Query       string
	StatusCode  int
	BytesSent   int64
	DurationMS  int64
	Blocked     bool
	ThreatScore int
	RuleID      *string
	UserAgent   string
}

// RequestLogFilter filters results from ListRequestLogs / CountRequestLogs.
type RequestLogFilter struct {
	SiteID   *string
	ClientIP string
	Blocked  *bool
	From     *time.Time
	To       *time.Time
	Limit    int // default 100, max 1000
	Offset   int
}

// ─── Store interface ──────────────────────────────────────────────────────────

// Store is the unified data-access interface for MetalWAF. All business logic
// depends only on this interface, allowing the underlying database to be
// swapped between editions without changing application code.
type Store interface {
	// Lifecycle
	Close() error
	Ping(ctx context.Context) error

	// ── Users
	CreateUser(ctx context.Context, u *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	UpdateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context) ([]*User, error)

	// ── Sessions
	CreateSession(ctx context.Context, s *Session) error
	GetSessionByToken(ctx context.Context, refreshToken string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error
	PruneExpiredSessions(ctx context.Context) error

	// ── Sites
	CreateSite(ctx context.Context, s *Site) error
	GetSiteByID(ctx context.Context, id string) (*Site, error)
	GetSiteByDomain(ctx context.Context, domain string) (*Site, error)
	UpdateSite(ctx context.Context, s *Site) error
	DeleteSite(ctx context.Context, id string) error
	ListSites(ctx context.Context) ([]*Site, error)

	// ── Upstreams
	CreateUpstream(ctx context.Context, u *Upstream) error
	GetUpstreamByID(ctx context.Context, id string) (*Upstream, error)
	ListUpstreamsBySite(ctx context.Context, siteID string) ([]*Upstream, error)
	UpdateUpstream(ctx context.Context, u *Upstream) error
	DeleteUpstream(ctx context.Context, id string) error

	// ── WAF Rules
	CreateWAFRule(ctx context.Context, r *WAFRule) error
	GetWAFRuleByID(ctx context.Context, id string) (*WAFRule, error)
	ListWAFRules(ctx context.Context, siteID *string) ([]*WAFRule, error)
	UpdateWAFRule(ctx context.Context, r *WAFRule) error
	DeleteWAFRule(ctx context.Context, id string) error

	// ── Certificates
	CreateCertificate(ctx context.Context, c *Certificate) error
	GetCertificateByID(ctx context.Context, id string) (*Certificate, error)
	UpdateCertificate(ctx context.Context, c *Certificate) error
	DeleteCertificate(ctx context.Context, id string) error
	ListCertificates(ctx context.Context) ([]*Certificate, error)

	// ── IP Lists
	CreateIPList(ctx context.Context, l *IPList) error
	GetIPListByID(ctx context.Context, id string) (*IPList, error)
	ListIPLists(ctx context.Context, siteID *string, listType *string) ([]*IPList, error)
	DeleteIPList(ctx context.Context, id string) error

	// ── Request Logs
	CreateRequestLog(ctx context.Context, l *RequestLog) error
	ListRequestLogs(ctx context.Context, f RequestLogFilter) ([]*RequestLog, error)
	CountRequestLogs(ctx context.Context, f RequestLogFilter) (int64, error)
	PurgeRequestLogs(ctx context.Context, before time.Time) (int64, error)
	TopClientIPs(ctx context.Context, f RequestLogFilter, limit int) ([]CountEntry, error)
	TopPaths(ctx context.Context, f RequestLogFilter, limit int) ([]CountEntry, error)
	TopRules(ctx context.Context, f RequestLogFilter, limit int) ([]CountEntry, error)
	StatusCodeDist(ctx context.Context, f RequestLogFilter) ([]CountEntry, error)
	RequestsPerSite(ctx context.Context, f RequestLogFilter) ([]CountEntry, error)

	// ── Settings
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)
}
