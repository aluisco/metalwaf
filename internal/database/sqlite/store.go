// Package sqlite provides the SQLite implementation of database.Store.
// It uses modernc.org/sqlite (pure Go, no CGO) so the final binary has zero
// external runtime dependencies.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/metalwaf/metalwaf/internal/database"
	_ "modernc.org/sqlite" // register "sqlite" driver
)

// Compile-time assertion: *Store must satisfy database.Store.
var _ database.Store = (*Store)(nil)

// Store is the SQLite-backed implementation of database.Store.
type Store struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database file at path, sets essential
// PRAGMAs and runs all pending schema migrations.
func New(ctx context.Context, path string) (*Store, error) {
	// Ensure the directory exists.
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("creating database directory %q: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite at %q: %w", path, err)
	}

	// SQLite supports only one concurrent writer; a single connection prevents
	// SQLITE_BUSY errors without needing external locking.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Apply safety and performance pragmas.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("setting %q: %w", pragma, err)
		}
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging sqlite: %w", err)
	}

	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &Store{db: db}, nil
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// ─── Helpers ──────────────────────────────────────────────────────────────────

func newID() string { return uuid.NewString() }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intToBool(n int) bool { return n != 0 }

func nullStr(v *string) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *v, Valid: true}
}

func nullTime(v *time.Time) sql.NullTime {
	if v == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *v, Valid: true}
}

// ─── Users ────────────────────────────────────────────────────────────────────

const userSelect = `SELECT id, username, email, password_hash, role, totp_secret, totp_enabled, created_at, updated_at FROM users`

func (s *Store) CreateUser(ctx context.Context, u *database.User) error {
	const q = `
		INSERT INTO users (id, username, email, password_hash, role, totp_secret, totp_enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if u.ID == "" {
		u.ID = newID()
	}
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, q,
		u.ID, u.Username, u.Email, u.PasswordHash, u.Role,
		u.TOTPSecret, boolInt(u.TOTPEnabled), u.CreatedAt, u.UpdatedAt,
	)
	return err
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*database.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+" WHERE id=?", id))
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*database.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+" WHERE username=?", username))
}

func (s *Store) UpdateUser(ctx context.Context, u *database.User) error {
	const q = `
		UPDATE users
		SET username=?, email=?, password_hash=?, role=?, totp_secret=?, totp_enabled=?, updated_at=?
		WHERE id=?`
	u.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q,
		u.Username, u.Email, u.PasswordHash, u.Role,
		u.TOTPSecret, boolInt(u.TOTPEnabled), u.UpdatedAt, u.ID,
	)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) ListUsers(ctx context.Context) ([]*database.User, error) {
	rows, err := s.db.QueryContext(ctx, userSelect+" ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*database.User
	for rows.Next() {
		u, err := scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func scanUser(row *sql.Row) (*database.User, error) {
	var u database.User
	var totpSecret sql.NullString
	var totpEnabled int
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role,
		&totpSecret, &totpEnabled, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.TOTPSecret = totpSecret.String
	u.TOTPEnabled = intToBool(totpEnabled)
	return &u, nil
}

func scanUserRow(rows *sql.Rows) (*database.User, error) {
	var u database.User
	var totpSecret sql.NullString
	var totpEnabled int
	err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role,
		&totpSecret, &totpEnabled, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.TOTPSecret = totpSecret.String
	u.TOTPEnabled = intToBool(totpEnabled)
	return &u, nil
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

func (s *Store) CreateSession(ctx context.Context, sess *database.Session) error {
	const q = `
		INSERT INTO sessions (id, user_id, refresh_token, expires_at, ip_address, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	if sess.ID == "" {
		sess.ID = newID()
	}
	sess.CreatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q,
		sess.ID, sess.UserID, sess.RefreshToken, sess.ExpiresAt,
		sess.IPAddress, sess.UserAgent, sess.CreatedAt,
	)
	return err
}

func (s *Store) GetSessionByToken(ctx context.Context, refreshToken string) (*database.Session, error) {
	const q = `
		SELECT id, user_id, refresh_token, expires_at, ip_address, user_agent, created_at
		FROM sessions WHERE refresh_token=?`
	var sess database.Session
	var ipAddr, userAgent sql.NullString
	err := s.db.QueryRowContext(ctx, q, refreshToken).Scan(
		&sess.ID, &sess.UserID, &sess.RefreshToken, &sess.ExpiresAt,
		&ipAddr, &userAgent, &sess.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sess.IPAddress = ipAddr.String
	sess.UserAgent = userAgent.String
	return &sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, id)
	return err
}

func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

func (s *Store) PruneExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < datetime('now')`)
	return err
}

// ─── Sites ────────────────────────────────────────────────────────────────────

const siteSelect = `SELECT id, name, domain, waf_mode, https_only, enabled, rate_limit_rps, rate_limit_burst, created_at, updated_at FROM sites`

func (s *Store) CreateSite(ctx context.Context, site *database.Site) error {
	const q = `
		INSERT INTO sites (id, name, domain, waf_mode, https_only, enabled, rate_limit_rps, rate_limit_burst, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if site.ID == "" {
		site.ID = newID()
	}
	now := time.Now().UTC()
	site.CreatedAt, site.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, q,
		site.ID, site.Name, site.Domain, site.WAFMode,
		boolInt(site.HTTPSOnly), boolInt(site.Enabled),
		site.RateLimitRPS, site.RateLimitBurst,
		site.CreatedAt, site.UpdatedAt,
	)
	return err
}

func (s *Store) GetSiteByID(ctx context.Context, id string) (*database.Site, error) {
	return scanSite(s.db.QueryRowContext(ctx, siteSelect+" WHERE id=?", id))
}

func (s *Store) GetSiteByDomain(ctx context.Context, domain string) (*database.Site, error) {
	return scanSite(s.db.QueryRowContext(ctx, siteSelect+" WHERE domain=?", domain))
}

func (s *Store) UpdateSite(ctx context.Context, site *database.Site) error {
	const q = `
		UPDATE sites SET name=?, domain=?, waf_mode=?, https_only=?, enabled=?,
		               rate_limit_rps=?, rate_limit_burst=?, updated_at=?
		WHERE id=?`
	site.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q,
		site.Name, site.Domain, site.WAFMode,
		boolInt(site.HTTPSOnly), boolInt(site.Enabled),
		site.RateLimitRPS, site.RateLimitBurst,
		site.UpdatedAt, site.ID,
	)
	return err
}

func (s *Store) DeleteSite(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sites WHERE id=?`, id)
	return err
}

func (s *Store) ListSites(ctx context.Context) ([]*database.Site, error) {
	rows, err := s.db.QueryContext(ctx, siteSelect+" ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []*database.Site
	for rows.Next() {
		site, err := scanSiteRow(rows)
		if err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}
	return sites, rows.Err()
}

func scanSite(row *sql.Row) (*database.Site, error) {
	var site database.Site
	var httpsOnly, enabled int
	err := row.Scan(&site.ID, &site.Name, &site.Domain, &site.WAFMode,
		&httpsOnly, &enabled, &site.RateLimitRPS, &site.RateLimitBurst,
		&site.CreatedAt, &site.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	site.HTTPSOnly = intToBool(httpsOnly)
	site.Enabled = intToBool(enabled)
	return &site, nil
}

func scanSiteRow(rows *sql.Rows) (*database.Site, error) {
	var site database.Site
	var httpsOnly, enabled int
	err := rows.Scan(&site.ID, &site.Name, &site.Domain, &site.WAFMode,
		&httpsOnly, &enabled, &site.RateLimitRPS, &site.RateLimitBurst,
		&site.CreatedAt, &site.UpdatedAt)
	if err != nil {
		return nil, err
	}
	site.HTTPSOnly = intToBool(httpsOnly)
	site.Enabled = intToBool(enabled)
	return &site, nil
}

// ─── Upstreams ────────────────────────────────────────────────────────────────

const upstreamSelect = `SELECT id, site_id, url, weight, enabled, created_at, updated_at FROM upstreams`

func (s *Store) CreateUpstream(ctx context.Context, u *database.Upstream) error {
	const q = `
		INSERT INTO upstreams (id, site_id, url, weight, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	if u.ID == "" {
		u.ID = newID()
	}
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, q,
		u.ID, u.SiteID, u.URL, u.Weight, boolInt(u.Enabled), u.CreatedAt, u.UpdatedAt,
	)
	return err
}

func (s *Store) GetUpstreamByID(ctx context.Context, id string) (*database.Upstream, error) {
	return scanUpstream(s.db.QueryRowContext(ctx, upstreamSelect+" WHERE id=?", id))
}

func (s *Store) ListUpstreamsBySite(ctx context.Context, siteID string) ([]*database.Upstream, error) {
	rows, err := s.db.QueryContext(ctx, upstreamSelect+" WHERE site_id=? ORDER BY weight DESC", siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*database.Upstream
	for rows.Next() {
		u, err := scanUpstreamRow(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, rows.Err()
}

func (s *Store) UpdateUpstream(ctx context.Context, u *database.Upstream) error {
	const q = `UPDATE upstreams SET url=?, weight=?, enabled=?, updated_at=? WHERE id=?`
	u.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q, u.URL, u.Weight, boolInt(u.Enabled), u.UpdatedAt, u.ID)
	return err
}

func (s *Store) DeleteUpstream(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM upstreams WHERE id=?`, id)
	return err
}

func scanUpstream(row *sql.Row) (*database.Upstream, error) {
	var u database.Upstream
	var enabled int
	err := row.Scan(&u.ID, &u.SiteID, &u.URL, &u.Weight, &enabled, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.Enabled = intToBool(enabled)
	return &u, nil
}

func scanUpstreamRow(rows *sql.Rows) (*database.Upstream, error) {
	var u database.Upstream
	var enabled int
	err := rows.Scan(&u.ID, &u.SiteID, &u.URL, &u.Weight, &enabled, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.Enabled = intToBool(enabled)
	return &u, nil
}

// ─── WAF Rules ────────────────────────────────────────────────────────────────

const wafRuleSelect = `SELECT id, site_id, name, description, field, operator, value, action, score, enabled, created_at, updated_at FROM waf_rules`

func (s *Store) CreateWAFRule(ctx context.Context, r *database.WAFRule) error {
	const q = `
		INSERT INTO waf_rules
		  (id, site_id, name, description, field, operator, value, action, score, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if r.ID == "" {
		r.ID = newID()
	}
	now := time.Now().UTC()
	r.CreatedAt, r.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, q,
		r.ID, nullStr(r.SiteID), r.Name, r.Description,
		r.Field, r.Operator, r.Value, r.Action,
		r.Score, boolInt(r.Enabled), r.CreatedAt, r.UpdatedAt,
	)
	return err
}

func (s *Store) GetWAFRuleByID(ctx context.Context, id string) (*database.WAFRule, error) {
	return scanWAFRule(s.db.QueryRowContext(ctx, wafRuleSelect+" WHERE id=?", id))
}

// ListWAFRules returns global rules when siteID is nil, or global + site-specific rules otherwise.
func (s *Store) ListWAFRules(ctx context.Context, siteID *string) ([]*database.WAFRule, error) {
	var rows *sql.Rows
	var err error
	if siteID == nil {
		rows, err = s.db.QueryContext(ctx, wafRuleSelect+" ORDER BY created_at")
	} else {
		rows, err = s.db.QueryContext(ctx,
			wafRuleSelect+" WHERE site_id IS NULL OR site_id=? ORDER BY created_at", *siteID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*database.WAFRule
	for rows.Next() {
		r, err := scanWAFRuleRow(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func (s *Store) UpdateWAFRule(ctx context.Context, r *database.WAFRule) error {
	const q = `
		UPDATE waf_rules
		SET site_id=?, name=?, description=?, field=?, operator=?, value=?, action=?, score=?, enabled=?, updated_at=?
		WHERE id=?`
	r.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q,
		nullStr(r.SiteID), r.Name, r.Description,
		r.Field, r.Operator, r.Value, r.Action,
		r.Score, boolInt(r.Enabled), r.UpdatedAt, r.ID,
	)
	return err
}

func (s *Store) DeleteWAFRule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM waf_rules WHERE id=?`, id)
	return err
}

func scanWAFRule(row *sql.Row) (*database.WAFRule, error) {
	var r database.WAFRule
	var siteID, description sql.NullString
	var enabled int
	err := row.Scan(&r.ID, &siteID, &r.Name, &description,
		&r.Field, &r.Operator, &r.Value, &r.Action,
		&r.Score, &enabled, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if siteID.Valid {
		r.SiteID = &siteID.String
	}
	r.Description = description.String
	r.Enabled = intToBool(enabled)
	return &r, nil
}

func scanWAFRuleRow(rows *sql.Rows) (*database.WAFRule, error) {
	var r database.WAFRule
	var siteID, description sql.NullString
	var enabled int
	err := rows.Scan(&r.ID, &siteID, &r.Name, &description,
		&r.Field, &r.Operator, &r.Value, &r.Action,
		&r.Score, &enabled, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if siteID.Valid {
		r.SiteID = &siteID.String
	}
	r.Description = description.String
	r.Enabled = intToBool(enabled)
	return &r, nil
}

// ─── Certificates ─────────────────────────────────────────────────────────────

const certSelect = `SELECT id, domain, source, cert_pem, key_pem, expires_at, auto_renew, created_at, updated_at FROM certificates`

func (s *Store) CreateCertificate(ctx context.Context, c *database.Certificate) error {
	const q = `
		INSERT INTO certificates
		  (id, domain, source, cert_pem, key_pem, expires_at, auto_renew, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if c.ID == "" {
		c.ID = newID()
	}
	now := time.Now().UTC()
	c.CreatedAt, c.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, q,
		c.ID, c.Domain, c.Source, c.CertPEM, c.KeyPEM,
		nullTime(c.ExpiresAt), boolInt(c.AutoRenew),
		c.CreatedAt, c.UpdatedAt,
	)
	return err
}

func (s *Store) GetCertificateByID(ctx context.Context, id string) (*database.Certificate, error) {
	return scanCertificate(s.db.QueryRowContext(ctx, certSelect+" WHERE id=?", id))
}

func (s *Store) UpdateCertificate(ctx context.Context, c *database.Certificate) error {
	const q = `
		UPDATE certificates
		SET domain=?, source=?, cert_pem=?, key_pem=?, expires_at=?, auto_renew=?, updated_at=?
		WHERE id=?`
	c.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q,
		c.Domain, c.Source, c.CertPEM, c.KeyPEM,
		nullTime(c.ExpiresAt), boolInt(c.AutoRenew),
		c.UpdatedAt, c.ID,
	)
	return err
}

func (s *Store) DeleteCertificate(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM certificates WHERE id=?`, id)
	return err
}

func (s *Store) ListCertificates(ctx context.Context) ([]*database.Certificate, error) {
	rows, err := s.db.QueryContext(ctx, certSelect+" ORDER BY domain")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*database.Certificate
	for rows.Next() {
		c, err := scanCertRow(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func scanCertificate(row *sql.Row) (*database.Certificate, error) {
	var c database.Certificate
	var expiresAt sql.NullTime
	var autoRenew int
	err := row.Scan(&c.ID, &c.Domain, &c.Source, &c.CertPEM, &c.KeyPEM,
		&expiresAt, &autoRenew, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		c.ExpiresAt = &expiresAt.Time
	}
	c.AutoRenew = intToBool(autoRenew)
	return &c, nil
}

func scanCertRow(rows *sql.Rows) (*database.Certificate, error) {
	var c database.Certificate
	var expiresAt sql.NullTime
	var autoRenew int
	err := rows.Scan(&c.ID, &c.Domain, &c.Source, &c.CertPEM, &c.KeyPEM,
		&expiresAt, &autoRenew, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		c.ExpiresAt = &expiresAt.Time
	}
	c.AutoRenew = intToBool(autoRenew)
	return &c, nil
}

// ─── Request Logs ─────────────────────────────────────────────────────────────

func (s *Store) CreateRequestLog(ctx context.Context, l *database.RequestLog) error {
	const q = `
		INSERT INTO request_logs
		  (id, site_id, timestamp, client_ip, method, host, path, query,
		   status_code, bytes_sent, duration_ms, blocked, threat_score, rule_id, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if l.ID == "" {
		l.ID = newID()
	}
	if l.Timestamp.IsZero() {
		l.Timestamp = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, q,
		l.ID, nullStr(l.SiteID), l.Timestamp,
		l.ClientIP, l.Method, l.Host, l.Path, l.Query,
		l.StatusCode, l.BytesSent, l.DurationMS,
		boolInt(l.Blocked), l.ThreatScore, nullStr(l.RuleID), l.UserAgent,
	)
	return err
}

func (s *Store) ListRequestLogs(ctx context.Context, f database.RequestLogFilter) ([]*database.RequestLog, error) {
	q, args := buildLogQuery(`
		SELECT id, site_id, timestamp, client_ip, method, host, path, query,
		       status_code, bytes_sent, duration_ms, blocked, threat_score, rule_id, user_agent`, f)
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*database.RequestLog
	for rows.Next() {
		l, err := scanLogRow(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, l)
	}
	return list, rows.Err()
}

func (s *Store) CountRequestLogs(ctx context.Context, f database.RequestLogFilter) (int64, error) {
	q, args := buildLogQuery("SELECT COUNT(*)", f)
	var count int64
	return count, s.db.QueryRowContext(ctx, q, args...).Scan(&count)
}

func buildLogWhere(f database.RequestLogFilter) (string, []any) {
	var conds []string
	var args []any
	if f.SiteID != nil {
		conds = append(conds, "site_id=?")
		args = append(args, *f.SiteID)
	}
	if f.ClientIP != "" {
		conds = append(conds, "client_ip=?")
		args = append(args, f.ClientIP)
	}
	if f.Blocked != nil {
		conds = append(conds, "blocked=?")
		args = append(args, boolInt(*f.Blocked))
	}
	if f.From != nil {
		conds = append(conds, "timestamp>=?")
		args = append(args, *f.From)
	}
	if f.To != nil {
		conds = append(conds, "timestamp<=?")
		args = append(args, *f.To)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func buildLogQuery(selectClause string, f database.RequestLogFilter) (string, []any) {
	where, args := buildLogWhere(f)
	return selectClause + " FROM request_logs" + where, args
}

func scanLogRow(rows *sql.Rows) (*database.RequestLog, error) {
	var l database.RequestLog
	var siteID, ruleID, query sql.NullString
	var blocked int
	err := rows.Scan(
		&l.ID, &siteID, &l.Timestamp,
		&l.ClientIP, &l.Method, &l.Host, &l.Path, &query,
		&l.StatusCode, &l.BytesSent, &l.DurationMS,
		&blocked, &l.ThreatScore, &ruleID, &l.UserAgent,
	)
	if err != nil {
		return nil, err
	}
	if siteID.Valid {
		l.SiteID = &siteID.String
	}
	if ruleID.Valid {
		l.RuleID = &ruleID.String
	}
	l.Query = query.String
	l.Blocked = intToBool(blocked)
	return &l, nil
}

// ─── IP Lists ─────────────────────────────────────────────────────────────────

func (s *Store) CreateIPList(ctx context.Context, l *database.IPList) error {
	const q = `
		INSERT INTO ip_lists (id, site_id, type, cidr, comment, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	if l.ID == "" {
		l.ID = newID()
	}
	l.CreatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q,
		l.ID, nullStr(l.SiteID), l.Type, l.CIDR, l.Comment, l.CreatedAt,
	)
	return err
}

func (s *Store) GetIPListByID(ctx context.Context, id string) (*database.IPList, error) {
	const q = `SELECT id, site_id, type, cidr, comment, created_at FROM ip_lists WHERE id=?`
	return scanIPList(s.db.QueryRowContext(ctx, q, id))
}

// ListIPLists returns entries filtered by optional siteID and/or listType.
// Pass nil to skip that filter.
func (s *Store) ListIPLists(ctx context.Context, siteID *string, listType *string) ([]*database.IPList, error) {
	var conds []string
	var args []any
	if siteID != nil {
		conds = append(conds, "site_id=?")
		args = append(args, *siteID)
	}
	if listType != nil {
		conds = append(conds, "type=?")
		args = append(args, *listType)
	}
	q := `SELECT id, site_id, type, cidr, comment, created_at FROM ip_lists`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY created_at"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*database.IPList
	for rows.Next() {
		entry, err := scanIPListRow(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	return list, rows.Err()
}

func (s *Store) DeleteIPList(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ip_lists WHERE id=?`, id)
	return err
}

func scanIPList(row *sql.Row) (*database.IPList, error) {
	var l database.IPList
	var siteID sql.NullString
	err := row.Scan(&l.ID, &siteID, &l.Type, &l.CIDR, &l.Comment, &l.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if siteID.Valid {
		l.SiteID = &siteID.String
	}
	return &l, nil
}

func scanIPListRow(rows *sql.Rows) (*database.IPList, error) {
	var l database.IPList
	var siteID sql.NullString
	err := rows.Scan(&l.ID, &siteID, &l.Type, &l.CIDR, &l.Comment, &l.CreatedAt)
	if err != nil {
		return nil, err
	}
	if siteID.Valid {
		l.SiteID = &siteID.String
	}
	return &l, nil
}

// ─── Analytics ────────────────────────────────────────────────────────────────

// PurgeRequestLogs deletes all request_logs entries older than before.
// Returns the number of deleted rows.
func (s *Store) PurgeRequestLogs(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM request_logs WHERE timestamp < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) TopClientIPs(ctx context.Context, f database.RequestLogFilter, limit int) ([]database.CountEntry, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := buildLogWhere(f)
	q := "SELECT client_ip AS label, COUNT(*) AS cnt FROM request_logs" + where +
		" GROUP BY client_ip ORDER BY cnt DESC LIMIT ?"
	args = append(args, limit)
	return queryCountEntries(ctx, s.db, q, args...)
}

func (s *Store) TopPaths(ctx context.Context, f database.RequestLogFilter, limit int) ([]database.CountEntry, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := buildLogWhere(f)
	q := "SELECT path AS label, COUNT(*) AS cnt FROM request_logs" + where +
		" GROUP BY path ORDER BY cnt DESC LIMIT ?"
	args = append(args, limit)
	return queryCountEntries(ctx, s.db, q, args...)
}

func (s *Store) TopRules(ctx context.Context, f database.RequestLogFilter, limit int) ([]database.CountEntry, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := buildLogWhere(f)
	extra := " AND rule_id IS NOT NULL"
	if where == "" {
		extra = " WHERE rule_id IS NOT NULL"
	}
	q := "SELECT rule_id AS label, COUNT(*) AS cnt FROM request_logs" + where + extra +
		" GROUP BY rule_id ORDER BY cnt DESC LIMIT ?"
	args = append(args, limit)
	return queryCountEntries(ctx, s.db, q, args...)
}

func (s *Store) StatusCodeDist(ctx context.Context, f database.RequestLogFilter) ([]database.CountEntry, error) {
	where, args := buildLogWhere(f)
	q := "SELECT CAST(status_code AS TEXT) AS label, COUNT(*) AS cnt FROM request_logs" + where +
		" GROUP BY status_code ORDER BY cnt DESC"
	return queryCountEntries(ctx, s.db, q, args...)
}

func (s *Store) RequestsPerSite(ctx context.Context, f database.RequestLogFilter) ([]database.CountEntry, error) {
	where, args := buildLogWhere(f)
	q := "SELECT COALESCE(site_id, 'global') AS label, COUNT(*) AS cnt FROM request_logs" + where +
		" GROUP BY site_id ORDER BY cnt DESC"
	return queryCountEntries(ctx, s.db, q, args...)
}

// queryCountEntries runs q with args and scans (label, cnt) rows into []CountEntry.
func queryCountEntries(ctx context.Context, db *sql.DB, q string, args ...any) ([]database.CountEntry, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []database.CountEntry
	for rows.Next() {
		var e database.CountEntry
		if err := rows.Scan(&e.Label, &e.Count); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ─── Settings ─────────────────────────────────────────────────────────────────

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	const q = `
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
	_, err := s.db.ExecContext(ctx, q, key, value)
	return err
}

func (s *Store) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		settings[k] = v
	}
	return settings, rows.Err()
}
