package waf

// traversalRules returns built-in Path Traversal / LFI detection signatures.
// Applied to URI and query string only (body is less common for traversal).
func traversalRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
	}
	sigs := []sig{
		// High-confidence: block immediately.
		{"TRAVERSAL-DOT-DOT", `(?:\.\.[\\/]){2,}`, 50, ActionBlock},
		{"TRAVERSAL-ENCODED", `(?i)\.\.(%2f|%5c|%2F|%5C|%252f|%255c)`, 50, ActionBlock},
		{"TRAVERSAL-NULL-BYTE", `%00`, 50, ActionBlock},

		// Medium-confidence: accumulate score.
		{"TRAVERSAL-LINUX-SENSITIVE", `(?i)\/(etc\/(passwd|shadow|group|hosts|sudoers)|proc\/(self|\d+)\/(environ|maps|cmdline|exe))`, 35, ActionDetect},
		{"TRAVERSAL-WIN-SENSITIVE", `(?i)(c:\\\\windows\\\\|\\\\win\.ini\b|system32\\\\cmd\.exe)`, 35, ActionDetect},
		{"TRAVERSAL-WEB-CONFIG", `(?i)(\.(htaccess|htpasswd|env|git|svn|DS_Store)|web\.config)`, 25, ActionDetect},
		{"TRAVERSAL-SINGLE-DOT-DOT", `(?:\.\.[/\\])`, 20, ActionDetect},
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
			})
		}
	}
	return rules
}
