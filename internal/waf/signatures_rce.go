package waf

// rceRules returns built-in Remote Code Execution / Command Injection signatures.
// Applied to URI, query string, and body.
func rceRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
	}
	sigs := []sig{
		// High-confidence: block immediately.
		{"RCE-PHP-EXEC", `(?i)\b(system|shell_exec|passthru|popen|proc_open)\s*\(`, 50, ActionBlock},
		{"RCE-CMD-SUBST", `\$\([^)]{1,200}\)`, 50, ActionBlock},
		{"RCE-BACKTICK", "`.{1,100}`", 50, ActionBlock},
		{"RCE-SHELL-CHAIN", `(?i)([;|&]{1,2})\s*(bash|sh|cmd|powershell|wget|curl|nc|netcat|python|perl|ruby)\b`, 50, ActionBlock},

		// Medium-confidence: accumulate score.
		{"RCE-CMD-INJECT", `(?i)([;|&]{1,2})\s*(ls|dir|cat|type|echo|whoami|id|uname|pwd|env|ifconfig|ipconfig)\b`, 35, ActionDetect},
		{"RCE-PHP-EVAL", `(?i)\b(eval|assert)\s*\(\s*\$`, 40, ActionDetect},
		{"RCE-SSTI", `(?i)\{\{[\s\S]{0,100}\}\}|<%[\s\S]{0,100}%>`, 30, ActionDetect},
		{"RCE-PYTHON-EXEC", `(?i)\b(__import__|subprocess\.|os\.system|os\.popen)\s*[\(\.]`, 40, ActionDetect},
	}

	inputFields := []string{FieldURI, FieldQuery, FieldBody}
	rules := make([]Rule, 0, len(sigs)*len(inputFields))
	for _, s := range sigs {
		for _, f := range inputFields {
			rules = append(rules, Rule{
				Name:     s.name + "_" + f,
				Category: CategoryRCE,
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
