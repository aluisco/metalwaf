package waf

// traversalRules returns built-in Path Traversal / LFI detection signatures.
// Applied to URI and query string only (body is less common for traversal).
func traversalRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
		level  int
	}
	sigs := []sig{
		// ── Level 1: high confidence block ───────────────────────────────────
		{"TRAVERSAL-DOT-DOT", `(?:\.\.[\\/]){2,}`, 50, ActionBlock, 1},
		{"TRAVERSAL-ENCODED", `(?i)\.\.(%2f|%5c|%2F|%5C|%252f|%255c)`, 50, ActionBlock, 1},
		{"TRAVERSAL-NULL-BYTE", `%00`, 50, ActionBlock, 1},
		{"TRAVERSAL-LINUX-SENSITIVE", `(?i)\/(etc\/(passwd|shadow|group|hosts|sudoers)|proc\/(self|\d+)\/(environ|maps|cmdline|exe))`, 50, ActionBlock, 1},
		{"TRAVERSAL-WIN-SENSITIVE", `(?i)(c:\\\\windows\\\\|\\\\win\.ini\b|system32\\\\cmd\.exe)`, 50, ActionBlock, 1},

		// ── Level 2: medium confidence ────────────────────────────────────────
		{"TRAVERSAL-WEB-CONFIG", `(?i)(\.(htaccess|htpasswd|env|git|svn|DS_Store)|web\.config)`, 35, ActionDetect, 2},
		{"TRAVERSAL-PROC-SELF", `/proc/self/(fd|root|cwd|mem|exe)`, 35, ActionDetect, 2},
		{"TRAVERSAL-ZIP-WRAPPER", `(?i)^zip://`, 35, ActionDetect, 2},

		// ── Level 3: low signal ───────────────────────────────────────────────
		{"TRAVERSAL-SINGLE-DOT-DOT", `(?:\.\.[/\\])`, 20, ActionDetect, 3},
	}

	pathFields := []string{FieldURI, FieldQuery}
	rules := make([]Rule, 0, len(sigs)*len(pathFields))
	for _, s := range sigs {
		for _, f := range pathFields {
			rules = append(rules, Rule{
				Name:     s.name + "_" + f,
				Category: CategoryTraversal,
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
