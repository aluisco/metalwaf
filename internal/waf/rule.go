package waf

import "github.com/metalwaf/metalwaf/internal/database"

// Field constants — the part of the HTTP request a rule inspects.
const (
	FieldURI       = "uri"
	FieldQuery     = "query"
	FieldBody      = "body"
	FieldIP        = "ip"
	FieldUserAgent = "user_agent"
	FieldMethod    = "method"
	// Header fields use the prefix "header:" followed by the header name,
	// e.g. "header:Content-Type".
)

// Operator constants — how the rule value is matched against the field.
const (
	OpContains    = "contains"
	OpNotContains = "not_contains"
	OpRegex       = "regex"
	OpEquals      = "equals"
	OpStartsWith  = "startswith"
	OpEndsWith    = "endswith"
	OpCIDR        = "cidr"
)

// Action constants — what the rule does when it matches.
const (
	// ActionBlock marks the request as blocked immediately (takes effect when
	// the site WAF mode is "block"). Score is still added to the total.
	ActionBlock = "block"

	// ActionDetect records the match and adds the score but does not set the
	// blocked flag by itself; blocking only occurs if the accumulated score
	// reaches the threshold.
	ActionDetect = "detect"

	// ActionAllow is an explicit whitelist: if this rule matches, inspection
	// stops immediately and the request is forwarded unconditionally.
	ActionAllow = "allow"
)

// Category labels for built-in signatures.
const (
	CategorySQLi      = "sqli"
	CategoryXSS       = "xss"
	CategoryRCE       = "rce"
	CategoryTraversal = "traversal"
	CategoryScanner   = "scanner"
	CategoryXXE       = "xxe"
	CategorySSRF      = "ssrf"
	CategoryCustom    = "custom"
)

// Rule is the unified representation used by the engine for both built-in
// signatures and custom rules loaded from the database.
type Rule struct {
	ID       string // empty for built-in rules
	SiteID   string // empty = applies to all sites
	Name     string
	Category string
	Field    string
	Operator string
	Value    string
	Score    int
	Action   string
	Builtin  bool
	// Level is the minimum paranoia level required to activate this rule.
	// 0 = always active (used for custom rules); 1–4 = paranoia threshold.
	Level int
}

// FromDB converts a database.WAFRule to a Rule.
func FromDB(r *database.WAFRule) Rule {
	siteID := ""
	if r.SiteID != nil {
		siteID = *r.SiteID
	}
	return Rule{
		ID:       r.ID,
		SiteID:   siteID,
		Name:     r.Name,
		Category: CategoryCustom,
		Field:    r.Field,
		Operator: r.Operator,
		Value:    r.Value,
		Score:    r.Score,
		Action:   r.Action,
		Builtin:  false,
	}
}
