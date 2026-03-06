package waf

// xxeRules returns built-in XML External Entity (XXE) injection detection signatures.
// Applied to body and query string fields.
// All patterns are Level 1 (high confidence, block immediately).
func xxeRules() []Rule {
	type sig struct {
		name  string
		value string
	}
	sigs := []sig{
		// Inline DOCTYPE + ENTITY combination — the classic XXE payload.
		{"XXE-DOCTYPE", `(?i)<!DOCTYPE[\s\S]{0,200}<!ENTITY`},
		// Named external entity via SYSTEM identifier.
		{"XXE-ENTITY-SYSTEM", `(?i)<!ENTITY\s+\w+\s+SYSTEM\b`},
		// Named external entity via PUBLIC identifier.
		{"XXE-ENTITY-PUBLIC", `(?i)<!ENTITY\s+\w+\s+PUBLIC\b`},
		// Parameter entity used for blind XXE / OOB exfiltration.
		{"XXE-PARAMETER", `(?i)<!ENTITY\s+%\s+\w+\s+SYSTEM\b`},
		// file:// URL in XML — reading local files.
		{"XXE-FILE-READ", `(?i)file:///(?:/etc/|/proc/|c:[/\\])`},
	}

	inputFields := []string{FieldBody, FieldQuery}
	rules := make([]Rule, 0, len(sigs)*len(inputFields))
	for _, s := range sigs {
		for _, f := range inputFields {
			rules = append(rules, Rule{
				Name:     s.name + "_" + f,
				Category: CategoryXXE,
				Field:    f,
				Operator: OpRegex,
				Value:    s.value,
				Score:    50,
				Action:   ActionBlock,
				Builtin:  true,
				Level:    1,
			})
		}
	}
	return rules
}
