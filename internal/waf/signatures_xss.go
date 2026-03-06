package waf

// xssRules returns built-in Cross-Site Scripting detection signatures.
// Applied to URI, query string, and body.
func xssRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
	}
	sigs := []sig{
		// High-confidence: block immediately.
		{"XSS-SCRIPT-TAG", `(?i)<\s*script[\s>\/]`, 50, ActionBlock},
		{"XSS-JS-PROTOCOL", `(?i)javascript\s*:`, 50, ActionBlock},
		{"XSS-EVENT-HANDLER", `(?i)\bon\w+\s*=\s*["']?[^"'\s>]`, 40, ActionBlock},

		// Medium-confidence: accumulate score.
		{"XSS-IFRAME-EMBED", `(?i)<\s*(iframe|object|embed)\b`, 35, ActionDetect},
		{"XSS-EVAL", `(?i)\beval\s*\(`, 30, ActionDetect},
		{"XSS-DOM-ACCESS", `(?i)\bdocument\s*\.\s*(cookie|location|write|domain)\b`, 30, ActionDetect},
		{"XSS-DATA-URI", `(?i)=\s*data\s*:[^,;]*;\s*base64`, 35, ActionDetect},
		{"XSS-CSS-EXPR", `(?i)\bexpression\s*\(`, 30, ActionDetect},
		{"XSS-SVG-SCRIPT", `(?i)<\s*svg[^>]*>[\s\S]{0,200}<\s*script`, 40, ActionDetect},
		{"XSS-VBSCRIPT", `(?i)vbscript\s*:`, 40, ActionDetect},
		{"XSS-TEMPLATE-LITERAL", `(?i)\$\{[^}]{0,100}\}`, 20, ActionDetect},
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
			})
		}
	}
	return rules
}
