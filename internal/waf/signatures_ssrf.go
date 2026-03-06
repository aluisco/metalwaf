package waf

// ssrfRules returns built-in Server-Side Request Forgery (SSRF) detection signatures.
// Applied to query string and body fields — places where URLs are typically supplied.
func ssrfRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
		level  int
	}
	sigs := []sig{
		// ── Level 1: block immediately (high confidence) ──────────────────────
		// Requests targeting localhost or loopback ranges.
		{"SSRF-LOCALHOST", `(?i)https?://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1)\b`, 40, ActionBlock, 1},
		// AWS instance metadata endpoint (IMDSv1).
		{"SSRF-METADATA-AWS", `169\.254\.169\.254`, 50, ActionBlock, 1},
		// GCP instance metadata endpoint.
		{"SSRF-METADATA-GCP", `(?i)metadata\.google\.internal`, 50, ActionBlock, 1},
		// Azure IMDS endpoint.
		{"SSRF-METADATA-AZURE", `(?i)metadata\.azure\b|169\.254\.169\.254`, 50, ActionBlock, 1},
		// Dangerous URL schemes that bypass HTTP restrictions.
		{"SSRF-SCHEME", `(?i)(?:dict|gopher|sftp|ldap|tftp)://`, 40, ActionBlock, 1},

		// ── Level 2: accumulate score (medium confidence) ─────────────────────
		// RFC-1918 private IP ranges in URL parameters (could be legitimate in VPNs).
		{"SSRF-PRIV-IP", `(?i)https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b`, 30, ActionDetect, 2},
	}

	inputFields := []string{FieldQuery, FieldBody}
	rules := make([]Rule, 0, len(sigs)*len(inputFields))
	for _, s := range sigs {
		for _, f := range inputFields {
			rules = append(rules, Rule{
				Name:     s.name + "_" + f,
				Category: CategorySSRF,
				Field:    f,
				Operator: OpRegex,
				Value:    s.value,
				Score:    s.score,
				Action:   s.action,
				Builtin:  true,
				Level:    s.level,
			})
		}
	}
	return rules
}
