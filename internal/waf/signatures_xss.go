package waf

// xssRules returns built-in Cross-Site Scripting detection signatures.
// Applied to URI, query string, and body.
func xssRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
		level  int
	}
	sigs := []sig{
		// ── Level 1: block immediately (high confidence) ─────────────────────
		{"XSS-SCRIPT-TAG", `(?i)<\s*script[\s>\/]`, 50, ActionBlock, 1},
		{"XSS-JS-PROTOCOL", `(?i)javascript\s*:`, 50, ActionBlock, 1},
		{"XSS-EVENT-HANDLER", `(?i)\bon\w+\s*=\s*["']?[^"'\s>]`, 40, ActionBlock, 1},
		{"XSS-BODY-ONLOAD", `(?i)<\s*body[^>]+onload\s*=`, 40, ActionBlock, 1},
		{"XSS-SVG-ONLOAD", `(?i)<\s*svg[^>]+onload\s*=`, 50, ActionBlock, 1},
		{"XSS-IFRAME-EMBED", `(?i)<\s*(iframe|object|embed)\b`, 35, ActionBlock, 1},
		{"XSS-DATA-URI-HTML", `(?i)=\s*data\s*:text/html`, 50, ActionBlock, 1},
		{"XSS-VBSCRIPT", `(?i)vbscript\s*:`, 50, ActionBlock, 1},

		// ── Level 2: accumulate score (medium confidence) ────────────────────
		{"XSS-EVAL", `(?i)\beval\s*\(`, 30, ActionDetect, 2},
		{"XSS-DOM-ACCESS", `(?i)\bdocument\s*\.\s*(cookie|location|write|domain)\b`, 30, ActionDetect, 2},
		{"XSS-DATA-URI-B64", `(?i)=\s*data\s*:[^,;]*;\s*base64`, 35, ActionDetect, 2},
		{"XSS-CSS-EXPR", `(?i)\bexpression\s*\(`, 30, ActionDetect, 2},
		{"XSS-SVG-SCRIPT", `(?i)<\s*svg[^>]*>[\s\S]{0,200}<\s*script`, 40, ActionDetect, 2},
		{"XSS-META-REFRESH", `(?i)<\s*meta[^>]+http-equiv\s*=\s*['"?]refresh`, 35, ActionDetect, 2},
		{"XSS-ANGULAR-TEMPLATE", `(?i)\b(constructor\.constructor|Function\s*\(\s*['"]return\s)`, 40, ActionDetect, 2},

		// ── Level 3: low signal (aggressive mode) ───────────────────────────
		{"XSS-TEMPLATE-LITERAL", `(?i)\$\{[^}]{0,100}\}`, 20, ActionDetect, 3},
	}

	inputFields := []string{FieldURI, FieldQuery, FieldBody}
	rules := make([]Rule, 0, len(sigs)*len(inputFields))
	for _, s := range sigs {
		for _, f := range inputFields {
			rules = append(rules, Rule{
				Name:     s.name + "_" + f,
				Category: CategoryXSS,
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
