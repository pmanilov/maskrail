package rules_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestGenConfigRuleCasesCasesCoverEveryLoadedRule(t *testing.T) {
	t.Parallel()

	_, rulesByID := loadRealConfigScanner(t)
	cases := realConfigRuleCases()
	covered := make(map[string]int, len(cases))
	for _, tt := range cases {
		if _, ok := rulesByID[tt.ruleID]; !ok {
			t.Fatalf("case %q references unknown rule %q", tt.name, tt.ruleID)
		}
		covered[tt.ruleID]++
	}

	var missing []string
	for id := range rulesByID {
		if covered[id] == 0 {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("missing cases for rule IDs: %s", strings.Join(missing, ", "))
	}
}

func TestRealConfigCaptureGroupDecisionsAreExplicit(t *testing.T) {
	t.Parallel()

	_, rulesByID := loadRealConfigScanner(t)

	fullMatchWithHelperGroups := map[string]struct{}{
		"access_tokens.microsoft-teams-webhook.gl": {},
		"credentials.jwt-base64.gl":                {},
	}
	singleCaptureOfManyGroups := map[string]struct{}{
		"access_tokens.facebook-access-token.gl":   {},
		"api_keys.dropbox-long-lived-api-token.gl": {},
		"api_keys.heroku-api-key-v2.gl":            {},
		"api_keys.lob-api-key.gl":                  {},
		"api_keys.sonar-api-token.gl":              {},
	}
	multipleCaptureAlternatives := map[string]struct{}{
		"access_tokens.generic-token-assignment":    {},
		"access_tokens.generic-token-prose":         {},
		"access_tokens.sourcegraph-access-token.gl": {},
		"api_keys.atlassian-api-token.gl":           {},
		"credentials.password":                      {},
		"credentials.curl-auth-header.gl":           {},
		"credentials.curl-auth-user.gl":             {},
		"credentials.kubernetes-secret-yaml.gl":     {},
		"pii.fin.cvc":                               {},
	}

	for _, rl := range rulesByID {
		re, err := regexp.Compile("(?m)" + rl.Regex)
		if err != nil {
			t.Fatalf("compile %s: %v", rl.ID, err)
		}

		switch {
		case len(rl.Masking.CaptureGroups) == 0 && re.NumSubexp() > 0:
			if _, ok := fullMatchWithHelperGroups[rl.ID]; !ok {
				t.Fatalf("%s is full-match with %d regex groups but has no explicit helper-group decision", rl.ID, re.NumSubexp())
			}
		case len(rl.Masking.CaptureGroups) == 1 && re.NumSubexp() > 1:
			if _, ok := singleCaptureOfManyGroups[rl.ID]; !ok {
				t.Fatalf("%s selects one capture group out of %d but has no explicit decision", rl.ID, re.NumSubexp())
			}
		case len(rl.Masking.CaptureGroups) > 1:
			if _, ok := multipleCaptureAlternatives[rl.ID]; !ok {
				t.Fatalf("%s has multiple capture groups %v but has no explicit alternative decision", rl.ID, rl.Masking.CaptureGroups)
			}
		}
	}
}
