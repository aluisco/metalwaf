package waf

// scannerRules returns built-in scanner and automated tool detection signatures.
// Applied to the User-Agent header only.
func scannerRules() []Rule {
	type sig struct {
		name   string
		value  string
		score  int
		action string
	}
	sigs := []sig{
		// Known offensive security tools — high confidence.
		{"SCANNER-SQLMAP", `(?i)\bsqlmap\b`, 50, ActionDetect},
		{"SCANNER-NIKTO", `(?i)\bnikto\b`, 50, ActionDetect},
		{"SCANNER-NMAP", `(?i)\bnmap\b`, 50, ActionDetect},
		{"SCANNER-MASSCAN", `(?i)\bmasscan\b`, 50, ActionDetect},
		{"SCANNER-DIRBUSTER", `(?i)\b(dirbuster|gobuster|wfuzz|ffuf|feroxbuster)\b`, 50, ActionDetect},
		{"SCANNER-NUCLEI", `(?i)\bnuclei\b`, 50, ActionDetect},
		{"SCANNER-ACUNETIX", `(?i)\bacunetix\b`, 50, ActionDetect},
		{"SCANNER-NESSUS", `(?i)\b(nessus|openvas)\b`, 50, ActionDetect},
		{"SCANNER-BURP", `(?i)\bburp\s*(suite|intruder|scanner)?\b`, 50, ActionDetect},
		{"SCANNER-ZAP", `(?i)\bZAP\b`, 50, ActionDetect},
		{"SCANNER-W3AF", `(?i)\bw3af\b`, 50, ActionDetect},
		{"SCANNER-METASPLOIT", `(?i)\bmsf|metasploit\b`, 50, ActionDetect},

		// Generic scanner patterns — medium confidence.
		{"SCANNER-GENERIC-VULN", `(?i)(vulnerability|scanner|exploit|pentest|security.?scan|brute.?force)`, 30, ActionDetect},
		{"SCANNER-EMPTY-UA", `^$`, 20, ActionDetect},
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
		})
	}
	return rules
}
