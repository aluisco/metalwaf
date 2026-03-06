package waf

// scannerRules returns built-in scanner and automated tool detection signatures.
// Applied to the User-Agent header only.
func scannerRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
		level  int
	}
	sigs := []sig{
		// ── Level 1: known offensive tools (block on detect) ─────────────────
		{"SCANNER-SQLMAP", `(?i)\bsqlmap\b`, 50, ActionDetect, 1},
		{"SCANNER-NIKTO", `(?i)\bnikto\b`, 50, ActionDetect, 1},
		{"SCANNER-NMAP", `(?i)\bnmap\b`, 50, ActionDetect, 1},
		{"SCANNER-MASSCAN", `(?i)\bmasscan\b`, 50, ActionDetect, 1},
		{"SCANNER-DIRBUSTER", `(?i)\b(dirbuster|gobuster|wfuzz|ffuf|feroxbuster)\b`, 50, ActionDetect, 1},
		{"SCANNER-NUCLEI", `(?i)\bnuclei\b`, 50, ActionDetect, 1},
		{"SCANNER-ACUNETIX", `(?i)\bacunetix\b`, 50, ActionDetect, 1},
		{"SCANNER-NESSUS", `(?i)\b(nessus|openvas)\b`, 50, ActionDetect, 1},
		{"SCANNER-BURP", `(?i)\bburp\s*(suite|intruder|scanner)?\b`, 50, ActionDetect, 1},
		{"SCANNER-ZAP", `(?i)\bZAP\b`, 50, ActionDetect, 1},
		{"SCANNER-W3AF", `(?i)\bw3af\b`, 50, ActionDetect, 1},
		{"SCANNER-METASPLOIT", `(?i)\bmsf|metasploit\b`, 50, ActionDetect, 1},
		{"SCANNER-WPSCAN", `(?i)\bwpscan\b`, 50, ActionDetect, 1},
		{"SCANNER-HYDRA", `(?i)\b(hydra|medusa|thc-hydra)\b`, 50, ActionDetect, 1},
		{"SCANNER-SHODAN", `(?i)\bshodanscan\b`, 50, ActionDetect, 1},
		{"SCANNER-CHAOS", `(?i)\bprojectdiscovery\b`, 50, ActionDetect, 1},

		// ── Level 2: generic patterns ─────────────────────────────────────────
		{"SCANNER-GENERIC-VULN", `(?i)(vulnerability|scanner|exploit|pentest|security.?scan|brute.?force)`, 30, ActionDetect, 2},
		{"SCANNER-DIRB", `(?i)\bdirb\b`, 35, ActionDetect, 2},

		// ── Level 3: low signal ──────────────────────────────────────────────
		{"SCANNER-EMPTY-UA", `^$`, 20, ActionDetect, 3},
	}

	rules := make([]Rule, 0, len(sigs))
	for _, s := range sigs {
		rules = append(rules, Rule{
			Name:     s.name,
			Category: CategoryScanner,
			Field:    FieldUserAgent,
			Operator: OpRegex,
			Value:    s.value,
			Score:    s.score,
			Action:   s.action,
			Builtin:  true,
			Level:    s.level,
		})
	}
	return rules
}
