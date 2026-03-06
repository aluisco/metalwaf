package waf

// sqliRules returns built-in SQL Injection detection signatures.
// Patterns are applied to URI, query string, and body.
// High-confidence patterns use ActionBlock; others use ActionDetect with scoring.
func sqliRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
	}
	sigs := []sig{
		// High-confidence: block immediately in block mode.
		{"SQLI-UNION-SELECT", `(?i)\bUNION\s+(ALL\s+)?SELECT\b`, 50, ActionBlock},
		{"SQLI-TIME-SLEEP", `(?i)\bSLEEP\s*\(\s*\d+|\bWAITFOR\s+DELAY\b|\bBENCHMARK\s*\(`, 50, ActionBlock},
		{"SQLI-DDL", `(?i)\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b`, 50, ActionBlock},
		{"SQLI-XP-CMDSHELL", `(?i)\bxp_cmdshell\b`, 50, ActionBlock},
		{"SQLI-FILE-OPS", `(?i)\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b`, 50, ActionBlock},

		// Medium-confidence: accumulate score.
		{"SQLI-OR-INJECT", `(?i)['"` + "`" + `]\s*(OR|AND)\s+[\w'"` + "`" + `\s]+=`, 30, ActionDetect},
		{"SQLI-SCHEMA-ENUM", `(?i)\bINFORMATION_SCHEMA\.(TABLES|COLUMNS|SCHEMATA)\b`, 25, ActionDetect},
		{"SQLI-STACKED", `(?i)['"];?\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\b`, 35, ActionDetect},
		{"SQLI-TAUTOLOGY", `(?i)\bOR\s+['"]?1['"]?\s*=\s*['"]?1`, 25, ActionDetect},
		{"SQLI-EXEC-SP", `(?i)\b(EXEC|EXECUTE)\s*\(\s*@|\bsp_\w+\b`, 40, ActionDetect},
		{"SQLI-HEX-ENCODE", `(?i)0x[0-9a-fA-F]{8,}`, 20, ActionDetect},
		{"SQLI-COMMENT-SEQ", `(?i)(--\s|#\s|\/\*[\s\S]*?\*\/)`, 15, ActionDetect},
	}

	inputFields := []string{FieldURI, FieldQuery, FieldBody}
	rules := make([]Rule, 0, len(sigs)*len(inputFields))
	for _, s := range sigs {
		for _, f := range inputFields {
			rules = append(rules, Rule{
				Name:     s.name + "_" + f,
				Category: CategorySQLi,
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
