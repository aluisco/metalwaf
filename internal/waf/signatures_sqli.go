package waf

// sqliRules returns built-in SQL Injection detection signatures.
// Patterns are applied to URI, query string, and body.
// Level 0 in sig → auto-assigned: ActionBlock→1, score≥35→2, else→3.
func sqliRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
		level  int
	}
	sigs := []sig{
		// ── Level 1: block immediately (high confidence) ──────────────────────
		{"SQLI-UNION-SELECT", `(?i)\bUNION\s+(ALL\s+)?SELECT\b`, 50, ActionBlock, 1},
		{"SQLI-TIME-SLEEP", `(?i)\bSLEEP\s*\(\s*\d+|\bWAITFOR\s+DELAY\b|\bBENCHMARK\s*\(`, 50, ActionBlock, 1},
		{"SQLI-PG-SLEEP", `(?i)\bpg_sleep\s*\(`, 50, ActionBlock, 1},
		{"SQLI-DDL", `(?i)\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b`, 50, ActionBlock, 1},
		{"SQLI-XP-CMDSHELL", `(?i)\bxp_cmdshell\b`, 50, ActionBlock, 1},
		{"SQLI-FILE-OPS", `(?i)\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b`, 50, ActionBlock, 1},
		{"SQLI-ERROR-EXTRACT", `(?i)\b(EXTRACTVALUE|UPDATEXML)\s*\(`, 50, ActionBlock, 1},
		{"SQLI-OUT-OF-BAND", `(?i)\bDNS_LOOKUP\b|load_file\s*\(\s*concat\s*\(|\bOPENROWSET\b`, 50, ActionBlock, 1},
		{"SQLI-BATCHED", `(?i);\s*(EXEC|INSERT|UPDATE|DELETE|CREATE|DROP)\b`, 40, ActionBlock, 1},

		// ── Level 2: accumulate score (medium confidence) ────────────────────
		{"SQLI-OR-INJECT", `(?i)['"` + "`" + `]\s*(OR|AND)\s+[\w'"` + "`" + `\s]+=`, 30, ActionDetect, 2},
		{"SQLI-SCHEMA-ENUM", `(?i)\bINFORMATION_SCHEMA\.(TABLES|COLUMNS|SCHEMATA)\b`, 25, ActionDetect, 2},
		{"SQLI-STACKED", `(?i)['"];?\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\b`, 35, ActionDetect, 2},
		{"SQLI-TAUTOLOGY", `(?i)\bOR\s+['"]?1['"]?\s*=\s*['"]?1`, 25, ActionDetect, 2},
		{"SQLI-EXEC-SP", `(?i)\b(EXEC|EXECUTE)\s*\(\s*@|\bsp_\w+\b`, 40, ActionDetect, 2},
		{"SQLI-DBMS-FINGER", `(?i)\b(mysql_version|@@version|@@datadir|mssql_version)\b`, 30, ActionDetect, 2},

		// ── Level 3: low-score signals (aggressive) ──────────────────────────
		{"SQLI-HEX-ENCODE", `(?i)0x[0-9a-fA-F]{8,}`, 20, ActionDetect, 3},
		{"SQLI-COMMENT-SEQ", `(?i)(--\s|#\s|\/\*[\s\S]*?\*\/)`, 15, ActionDetect, 3},
	}

	inputFields := []string{FieldURI, FieldQuery, FieldBody}
	rules := make([]Rule, 0, len(sigs)*len(inputFields))
	for _, s := range sigs {
		lvl := s.level
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
				Level:    lvl,
			})
		}
	}
	return rules
}
