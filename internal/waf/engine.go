// Package waf implements the MetalWAF inspection engine.
// It evaluates HTTP requests against built-in signatures (SQLi, XSS, RCE,
// path traversal, scanner detection) and custom rules stored in the database,
// using an anomaly-scoring model similar to OWASP ModSecurity CRS.
package waf

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/metalwaf/metalwaf/internal/database"
)

// DefaultThreshold is the anomaly score at which a request is blocked.
// Individual ActionBlock rules bypass this threshold.
const DefaultThreshold = 100

// blocked403 is the HTML page returned to clients whose requests are blocked.
const blocked403 = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>403 Forbidden — MetalWAF</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .card{background:#1e293b;border-radius:12px;padding:48px;text-align:center;max-width:480px}
  h1{font-size:2.5rem;margin:0 0 8px;color:#f87171}
  p{color:#94a3b8;margin:8px 0}
  small{color:#475569;font-size:.75rem}
</style>
</head>
<body>
<div class="card">
  <h1>403</h1>
  <p><strong>Request Blocked</strong></p>
  <p>This request has been blocked by MetalWAF security policy.</p>
  <small>If you believe this is an error, contact the site administrator.</small>
</div>
</body>
</html>`

// ─── Internal compiled rule ───────────────────────────────────────────────────

// compiledRule wraps a Rule with pre-compiled regex and CIDR for performance.
// Compilation happens once at load time; every request reuses the same objects.
type compiledRule struct {
	Rule
	re  *regexp.Regexp
	net *net.IPNet
}

func compileRule(r Rule) compiledRule {
	cr := compiledRule{Rule: r}
	switch r.Operator {
	case OpRegex:
		if re, err := regexp.Compile(r.Value); err == nil {
			cr.re = re
		} else {
			slog.Warn("waf: ignoring rule with invalid regex",
				"rule", r.Name, "pattern", r.Value, "error", err)
		}
	case OpCIDR:
		if _, network, err := net.ParseCIDR(r.Value); err == nil {
			cr.net = network
		} else {
			slog.Warn("waf: ignoring rule with invalid CIDR",
				"rule", r.Name, "cidr", r.Value, "error", err)
		}
	}
	return cr
}

// matchValue returns true if input matches compiledRule according to its operator.
func matchValue(cr compiledRule, input string) bool {
	switch cr.Operator {
	case OpContains:
		return strings.Contains(strings.ToLower(input), strings.ToLower(cr.Value))
	case OpEquals:
		return strings.EqualFold(input, cr.Value)
	case OpStartsWith:
		return strings.HasPrefix(strings.ToLower(input), strings.ToLower(cr.Value))
	case OpEndsWith:
		return strings.HasSuffix(strings.ToLower(input), strings.ToLower(cr.Value))
	case OpRegex:
		return cr.re != nil && cr.re.MatchString(input)
	case OpCIDR:
		if cr.net == nil {
			return false
		}
		ip := net.ParseIP(input)
		return ip != nil && cr.net.Contains(ip)
	}
	return false
}

// ─── Result types ─────────────────────────────────────────────────────────────

// MatchedRule records which rule fired and on which field / sample input.
type MatchedRule struct {
	Rule   Rule
	Field  string
	Sample string // first 100 chars of the input that triggered the rule
}

// InspectResult holds the outcome of inspecting one request.
type InspectResult struct {
	Blocked      bool
	Score        int
	MatchedRules []MatchedRule
}

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine is the WAF inspection engine. It holds compiled built-in signatures
// merged with custom rules loaded from the database.
type Engine struct {
	store     database.Store
	mu        sync.RWMutex
	all       []compiledRule // builtin + custom, ready to iterate
	threshold int
}

// New creates an Engine with the built-in rule set pre-loaded.
// Custom rules from the database are added by calling Reload.
func New(store database.Store, threshold int) *Engine {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	e := &Engine{store: store, threshold: threshold}
	e.all = compileAll(allBuiltinRules(), nil)
	return e
}

// RuleCount returns the total number of compiled rules (built-in + custom).
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.all)
}

// Reload fetches custom rules from the database and merges them with the
// built-in signatures. Safe to call concurrently with Inspect.
func (e *Engine) Reload(ctx context.Context) error {
	dbRules, err := e.store.ListWAFRules(ctx, nil) // nil = load global rules
	if err != nil {
		return fmt.Errorf("waf reload: %w", err)
	}

	var custom []Rule
	for _, r := range dbRules {
		if r.Enabled {
			custom = append(custom, FromDB(r))
		}
	}

	compiled := compileAll(allBuiltinRules(), custom)

	e.mu.Lock()
	e.all = compiled
	e.mu.Unlock()

	slog.Info("waf: rules loaded",
		"builtin", len(allBuiltinRules()),
		"custom", len(custom),
		"total", len(compiled),
	)
	return nil
}

// compileAll combines built-in and custom rules into a compiled slice.
func compileAll(builtin, custom []Rule) []compiledRule {
	out := make([]compiledRule, 0, len(builtin)+len(custom))
	for _, r := range builtin {
		out = append(out, compileRule(r))
	}
	for _, r := range custom {
		out = append(out, compileRule(r))
	}
	return out
}

// allBuiltinRules aggregates all built-in signature sets.
func allBuiltinRules() []Rule {
	rules := make([]Rule, 0, 256)
	rules = append(rules, sqliRules()...)
	rules = append(rules, xssRules()...)
	rules = append(rules, rceRules()...)
	rules = append(rules, traversalRules()...)
	rules = append(rules, scannerRules()...)
	return rules
}

// ─── Inspection ───────────────────────────────────────────────────────────────

// Inspect evaluates r against all WAF rules for the given site.
//
// Pipeline:
//  1. If site.WAFMode == "off", skip all inspection.
//  2. Extract request fields (URI, query, body, IP, headers).
//  3. Evaluate every rule; skip rules scoped to a different site.
//  4. ActionAllow match → stop, forward unconditionally.
//  5. ActionBlock match → set Blocked=true, add score.
//  6. ActionDetect match → add score only.
//  7. After all rules: if accumulated score >= threshold, set Blocked=true.
//  8. If site.WAFMode == "detect", clear Blocked (log only, never block).
func (e *Engine) Inspect(r *http.Request, site *database.Site) *InspectResult {
	if site.WAFMode == "off" {
		return &InspectResult{}
	}

	fields := Extract(r)

	e.mu.RLock()
	rules := e.all
	e.mu.RUnlock()

	result := &InspectResult{}

	for _, cr := range rules {
		// Skip rules scoped to a specific site that isn't this one.
		if cr.SiteID != "" && cr.SiteID != site.ID {
			continue
		}

		value := fields.getValue(cr.Field)
		if value == "" {
			continue
		}

		if !matchValue(cr, value) {
			continue
		}

		// Truncate sample to avoid logging large payloads.
		sample := value
		if len(sample) > 100 {
			sample = sample[:100] + "…"
		}
		result.MatchedRules = append(result.MatchedRules, MatchedRule{
			Rule:   cr.Rule,
			Field:  cr.Field,
			Sample: sample,
		})

		switch cr.Action {
		case ActionAllow:
			// Explicit whitelist: stop inspection and forward.
			return &InspectResult{}
		case ActionBlock:
			result.Score += cr.Score
			result.Blocked = true
		case ActionDetect:
			result.Score += cr.Score
		}
	}

	// Anomaly threshold: blocks even if no individual rule used ActionBlock.
	if result.Score >= e.threshold {
		result.Blocked = true
	}

	// Detect mode: record matches but never block.
	if site.WAFMode == "detect" {
		result.Blocked = false
	}

	return result
}

// WriteBlocked writes the 403 Forbidden response to w.
// Called by the proxy handler when Inspect returns Blocked=true.
func WriteBlocked(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-MetalWAF-Blocked", "1")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(blocked403))
}
