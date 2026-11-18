// Modified in this fork: candidate-only builtin exclusion contract coverage.
package sensitive_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/registry"
	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/rule"
	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/scanners/sensitive"
)

func TestSecretExclusions_CandidateOnlyAndAdjacentCandidates(t *testing.T) {
	t.Parallel()

	rl := exclusionTestRule()
	rl.Regex = `(?:allowlisted[ \t]+)?token=([A-Za-z]+)`
	rl.SecretExclusions = []string{`allowlisted`}
	text := "allowlisted token=Secret token=allowlisted token=Second"

	assertExclusionScan(t, []rule.Rule{rl}, text, []sensitive.Match{
		exclusionTestMatch(rl, text, "Secret"),
		exclusionTestMatch(rl, text, "Second"),
	})
}

func TestSecretExclusions_EmptyListPreservesCandidates(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		exclusions []string
	}{
		{name: "absent"},
		{name: "explicit empty", exclusions: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rl := exclusionTestRule()
			rl.SecretExclusions = tc.exclusions
			text := "token=First token=Second"
			assertExclusionScan(t, []rule.Rule{rl}, text, []sensitive.Match{
				exclusionTestMatch(rl, text, "First"),
				exclusionTestMatch(rl, text, "Second"),
			})
		})
	}
}

func TestSecretExclusions_LoadedCaseAndMultilineSemantics(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`guardrails_regex_rules:
  - data_type: 3
    name: tokens
    rules:
      - rule_id: test.exclusions
        name: exclusion test
        regex: '(?s)token="([^"]+)"'
        secret_exclusions:
          - '^KeepCASE$'
          - '^IGNORE$'
        masking:
          capture_groups: [1]
          placeholder: TOKEN
`), 0600))
	_, rules, err := rule.LoadAll(path)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	// Case-sensitive patterns must survive YAML loading unchanged. Anchors in
	// exclusions use the same multiline semantics as the detection regex.
	text := "token=\"KeepCASE\" token=\"keepcase\" token=\"before\nIGNORE\nafter\" token=\"Secret\""
	assertExclusionScan(t, rules, text, []sensitive.Match{
		exclusionTestMatch(rules[0], text, "keepcase"),
		exclusionTestMatch(rules[0], text, "Secret"),
	})
}

func TestSecretExclusions_BuildRejectsInvalidPatterns(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		pattern string
	}{
		{name: "invalid", pattern: `(`},
		{name: "empty", pattern: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rl := exclusionTestRule()
			rl.SecretExclusions = []string{`^SAFE$`, tc.pattern}
			_, err := registry.Build(rl)
			require.Error(t, err)
			require.ErrorContains(t, err, rl.ID)
			require.ErrorContains(t, err, "exclusion 1")
		})
	}
}

func TestSecretExclusions_DoNotDisableProviderRule(t *testing.T) {
	t.Parallel()

	generic := exclusionTestRule()
	generic.SecretExclusions = []string{`^provider_[A-Za-z]+$`}
	generic.Regex = `token=([A-Za-z_]+)`
	provider := rule.Rule{
		ID:       "test.provider",
		Name:     "provider test",
		DataType: 3,
		Regex:    `(provider_[A-Za-z]+)`,
		Masking: rule.MaskingConfig{
			CaptureGroups: []int{1},
			Placeholder:   "PROVIDER",
		},
	}
	text := "token=provider_Secret token=Other"
	assertExclusionScan(t, []rule.Rule{generic, provider}, text, []sensitive.Match{
		exclusionTestMatch(provider, text, "provider_Secret"),
		exclusionTestMatch(generic, text, "Other"),
	})
}

func TestSecretExclusions_JSONCannotPersistOrAcceptBuiltinFilters(t *testing.T) {
	t.Parallel()

	rl := exclusionTestRule()
	rl.SecretExclusions = []string{`^Secret$`}
	text := "token=Secret"
	assertExclusionScan(t, []rule.Rule{rl}, text, nil)

	encoded, err := json.Marshal(rl)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))
	require.NotContains(t, fields, "secret_exclusions")
	require.NotContains(t, fields, "SecretExclusions")

	var restored rule.Rule
	require.NoError(t, json.Unmarshal(encoded, &restored))
	assertExclusionScan(t, []rule.Rule{restored}, text, []sensitive.Match{
		exclusionTestMatch(restored, text, "Secret"),
	})

	for _, key := range []string{"secret_exclusions", "SecretExclusions"} {
		t.Run(key, func(t *testing.T) {
			fields[key] = json.RawMessage(`["^Secret$"]`)
			incoming, err := json.Marshal(fields)
			require.NoError(t, err)
			var custom rule.Rule
			require.NoError(t, json.Unmarshal(incoming, &custom))
			assertExclusionScan(t, []rule.Rule{custom}, text, []sensitive.Match{
				exclusionTestMatch(custom, text, "Secret"),
			})
			delete(fields, key)
		})
	}
}

func exclusionTestRule() rule.Rule {
	return rule.Rule{
		ID:       "test.exclusions",
		Name:     "exclusion test",
		DataType: 3,
		Regex:    `token=([A-Za-z]+)`,
		Masking: rule.MaskingConfig{
			CaptureGroups: []int{1},
			Placeholder:   "TOKEN",
		},
	}
}

func exclusionTestMatch(rl rule.Rule, text, value string) sensitive.Match {
	start := strings.Index(text, value)
	return sensitive.Match{
		RuleID:      rl.ID,
		DataType:    rl.DataType,
		Start:       start,
		End:         start + len(value),
		FullText:    value,
		Placeholder: rl.Masking.Placeholder,
	}
}

func assertExclusionScan(t *testing.T, rules []rule.Rule, text string, want []sensitive.Match) {
	t.Helper()

	reg, err := registry.Build(rules...)
	require.NoError(t, err)
	ids := make([]string, 0, len(rules))
	for _, rl := range rules {
		ids = append(ids, rl.ID)
	}
	for _, prefilter := range []bool{false, true} {
		scanner := sensitive.New(reg, sensitive.WithKeywordPrefilter(prefilter))
		got, err := scanner.Scan(text, ids)
		require.NoError(t, err)
		if len(want) == 0 {
			require.Empty(t, got, "keyword prefilter: %t", prefilter)
		} else {
			require.Equal(t, want, got, "keyword prefilter: %t", prefilter)
		}
		for _, match := range got {
			require.Equal(t, match.FullText, text[match.Start:match.End])
		}
	}
}
