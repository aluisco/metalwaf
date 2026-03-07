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
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/metalwaf/metalwaf/internal/database"
)

// DefaultThreshold is the anomaly score at which a request is blocked.
// Individual ActionBlock rules bypass this threshold.
const DefaultThreshold = 100

// DefaultParanoia is the paranoia level used when no setting is configured.
// Level 2 includes high-confidence block rules and medium-confidence detect
// rules (behaviour equivalent to the pre-Phase-9 baseline).
const DefaultParanoia = 2

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
	case OpNotContains:
		return !strings.Contains(strings.ToLower(input), strings.ToLower(cr.Value))
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
	paranoia  int // active paranoia level (1–4)
}

// New creates an Engine with the built-in rule set pre-loaded.
// Custom rules from the database are added by calling Reload.
func New(store database.Store, threshold int) *Engine {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	e := &Engine{store: store, threshold: threshold, paranoia: DefaultParanoia}
	e.all = compileAll(allBuiltinRules(), nil, e.paranoia)
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

	// Read paranoia level from settings; keep current level on error.
	paranoia := e.paranoia
	if e.store != nil {
		if s, serr := e.store.GetSetting(ctx, "waf_paranoia_level"); serr == nil && s != "" {
			if n, nerr := strconv.Atoi(s); nerr == nil && n >= 1 && n <= 4 {
				paranoia = n
			}
		}
	}

	var custom []Rule
	for _, r := range dbRules {
		if r.Enabled {
			custom = append(custom, FromDB(r))
		}
	}

	compiled := compileAll(allBuiltinRules(), custom, paranoia)

	e.mu.Lock()
	e.all = compiled
	e.paranoia = paranoia
	e.mu.Unlock()

	slog.Info("waf: rules loaded",
		"builtin", len(allBuiltinRules()),
		"custom", len(custom),
		"total", len(compiled),
		"paranoia_level", paranoia,
	)
	return nil
}

// compileAll combines built-in and custom rules into a compiled slice.
// Built-in rules with Level > paranoia are skipped (Level 0 = always include).
func compileAll(builtin, custom []Rule, paranoia int) []compiledRule {
	out := make([]compiledRule, 0, len(builtin)+len(custom))
	for _, r := range builtin {
		if r.Level > 0 && r.Level > paranoia {
			continue
		}
		out = append(out, compileRule(r))
	}
	for _, r := range custom {
		// Custom rules have Level==0 and are always included.
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
	rules = append(rules, xxeRules()...)
	rules = append(rules, ssrfRules()...)
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

	// Monitor mode: record matches but never block.
	if site.WAFMode == "monitor" {
		result.Blocked = false
	}

	return result
}

// ─── Additional Engine methods ────────────────────────────────────────────────

// SetParanoiaLevel updates the paranoia level and triggers recompilation.
// Safe to call at runtime; takes effect immediately.
func (e *Engine) SetParanoiaLevel(level int) {
	if level < 1 {
		level = 1
	}
	if level > 4 {
		level = 4
	}
	e.mu.Lock()
	e.paranoia = level
	e.mu.Unlock()
}

// ParanoiaLevel returns the current paranoia level.
func (e *Engine) ParanoiaLevel() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.paranoia
}

// CategorySummary holds the rule count breakdown for one category.
type CategorySummary struct {
	Category string `json:"category"`
	Builtin  int    `json:"builtin"`
	Custom   int    `json:"custom"`
	Total    int    `json:"total"`
}

// Categories returns a summary of compiled rules grouped by category.
func (e *Engine) Categories() []CategorySummary {
	e.mu.RLock()
	defer e.mu.RUnlock()

	type kv struct{ b, c int }
	m := make(map[string]*kv)
	for _, cr := range e.all {
		if _, ok := m[cr.Category]; !ok {
			m[cr.Category] = &kv{}
		}
		if cr.Builtin {
			m[cr.Category].b++
		} else {
			m[cr.Category].c++
		}
	}

	out := make([]CategorySummary, 0, len(m))
	for cat, cnt := range m {
		out = append(out, CategorySummary{
			Category: cat,
			Builtin:  cnt.b,
			Custom:   cnt.c,
			Total:    cnt.b + cnt.c,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out
}

// BuiltinRules returns a snapshot of all currently-active built-in rules.
func (e *Engine) BuiltinRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []Rule
	for _, cr := range e.all {
		if cr.Builtin {
			out = append(out, cr.Rule)
		}
	}
	return out
}

// WriteBlocked writes the 403 Forbidden response to w.
// Called by the proxy handler when Inspect returns Blocked=true.
func WriteBlocked(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-MetalWAF-Blocked", "1")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(blocked403))
}
