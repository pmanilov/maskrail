// Modified in this fork: verify generated rules through the production scanner.
package gitleaksgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tomlsrc "github.com/cloud-ru-tech/guardrails-llm-filter/pkg/gitleaksgen/toml"
	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/registry"
	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/rule"
	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/scanners/sensitive"
)

func TestBuildFMGuardrailsRegexRulesFromConfig_SemanticSpans(t *testing.T) {
	t.Parallel()

	const hex40 = "0123456789abcdef" + "fedcba9876543210" + "a1b2c3d4"
	const legacyAtlassian = "AbCdEfGhIjKlMnOpQrStabcd"
	modernAtlassian := "ATATT3" + strings.Repeat("Ab3dEf7hIj9lMn2pQr5tUv8xYz0_", 7)[:186]
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.AbCdEfGhIjKlMnOp"
	sentry := "sntrys_eyJpYXQiOAb3dEf7hIj9lLCJyZWdpb25fdXJsMn2pQr5tUv8x_" + strings.Repeat("Ab3dEf7hIj9", 4)[:43]
	base64JWT := "ZXlKaGJHY2lPaU" + strings.Repeat("Ab3dEf7hIj9", 4)
	cases := []struct {
		name string
		src  tomlsrc.Rule
		text string
		want []string
	}{
		{"single capture", tomlsrc.Rule{ID: "single-group-api-key", Regex: `prefix-([a-z0-9]{8})(?:\s|$)`}, "prefix-a1b2c3d4 tail", []string{"a1b2c3d4"}},
		{"explicit secret group", tomlsrc.Rule{ID: "sonar-api-token", Regex: `(?i)sonar(login|token)=((?:squ_)?[a-z0-9]{40})`, SecretGroup: 2}, "sonartoken=squ_" + hex40, []string{"squ_" + hex40}},
		{"atlassian alternatives", tomlsrc.Rule{ID: "atlassian-api-token", Regex: `unused`}, "jira_token=" + legacyAtlassian + "\n" + modernAtlassian, []string{legacyAtlassian, modernAtlassian}},
		{"atlassian unrelated label", tomlsrc.Rule{ID: "atlassian-api-token", Regex: `unused`}, "jira_issue_id=" + legacyAtlassian + "\nConfluence page: " + legacyAtlassian, nil},
		{"sourcegraph alternatives", tomlsrc.Rule{ID: "sourcegraph-access-token", Regex: `unused`}, "sgp_" + hex40 + "\nsgp_local_" + hex40 + "\nsgp_0123456789abcdef_" + hex40 + "\nsourcegraph_token=" + hex40, []string{"sgp_" + hex40, "sgp_local_" + hex40, "sgp_0123456789abcdef_" + hex40, hex40}},
		{"sourcegraph bare hash", tomlsrc.Rule{ID: "sourcegraph-access-token", Regex: `unused`}, "sourcegraph\n" + hex40, nil},
		{"forced full match", tomlsrc.Rule{ID: "jwt-base64", Regex: `\bZXlK(?:(?P<alg>aGJHY2lPaU))[a-zA-Z0-9]{40,}`}, "(" + base64JWT + ")", []string{base64JWT}},
		{"sentry delimiter", tomlsrc.Rule{ID: "sentry-org-token", Regex: `unused`}, sentry + ",", []string{sentry}},
		{"hcl password", tomlsrc.Rule{ID: "hashicorp-tf-password", Regex: `unused`}, `password = "Ab3dEf7hIj9l",`, []string{"Ab3dEf7hIj9l"}},
		{"curl double quotes", tomlsrc.Rule{ID: "curl-auth-user", Regex: `unused`}, `curl -u "api-user:secretPass123", https://example.test`, []string{"api-user:secretPass123"}},
		{"curl single quotes", tomlsrc.Rule{ID: "curl-auth-user", Regex: `unused`}, `curl --user='api-user:secretPass123')`, []string{"api-user:secretPass123"}},
		{"curl bare", tomlsrc.Rule{ID: "curl-auth-user", Regex: `unused`}, `curl -u api-user:secretPass123;`, []string{"api-user:secretPass123"}},
		{"jwt punctuation", tomlsrc.Rule{ID: "jwt", Regex: `unused`}, `{"token":"` + jwt + `"}`, []string{jwt}},
		{"session cookie", tomlsrc.Rule{ID: "gitlab-session-cookie", Regex: `unused`}, `_gitlab_session=` + "0123456789abcdef" + "fedcba9876543210" + `; Path=/`, []string{"0123456789abcdef" + "fedcba9876543210"}},
		{"kubernetes kind first", tomlsrc.Rule{ID: "kubernetes-secret-yaml", Regex: `unused`}, "kind: Secret\ndata:\n  password: QWIzZEVmN2hJajls\n", []string{"QWIzZEVmN2hJajls"}},
		{"kubernetes data first", tomlsrc.Rule{ID: "kubernetes-secret-yaml", Regex: `unused`}, "data:\n  password: QWIzZEVmN2hJajls\nkind: Secret\n", []string{"QWIzZEVmN2hJajls"}},
		{"sidekiq url", tomlsrc.Rule{ID: "sidekiq-sensitive-url", Regex: `unused`}, "https://a1b2c3d4:5e6f7890@gems.contribsys.com/path", []string{"https://a1b2c3d4:5e6f7890@gems.contribsys.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner, ids := generatedScanner(t, tomlsrc.Config{Rules: []tomlsrc.Rule{tc.src}}, DefaultGitleaksPolicy())
			assertGeneratedScan(t, scanner, ids, tc.text, tc.want...)
		})
	}
}

func TestBuildFMGuardrailsRegexRulesFromConfig_PromptBoundaries(t *testing.T) {
	t.Parallel()

	for _, delimiter := range []string{"", " ", "'", `"`, "`", ";", ",", ":", "!", "?", "(", ")", "[", "]", "{", "}", `\n`, `\r`} {
		t.Run("capture/"+delimiter, func(t *testing.T) {
			src := tomlsrc.Rule{ID: "capture-token", Regex: `token=([a-z0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)`}
			scanner, ids := generatedScanner(t, tomlsrc.Config{Rules: []tomlsrc.Rule{src}}, DefaultGitleaksPolicy())
			assertGeneratedScan(t, scanner, ids, "token=a1b2c3d4"+delimiter, "a1b2c3d4")
			assertGeneratedScan(t, scanner, ids, "token=a1b2c3d4extra")
		})
	}
	// Without a semantic capture the original full-match boundary is retained.
	src := tomlsrc.Rule{ID: "full-match-token", Regex: `token=[a-z0-9]{8}(?:[\x60'"\s;]|\\[nr]|$)`}
	scanner, ids := generatedScanner(t, tomlsrc.Config{Rules: []tomlsrc.Rule{src}}, DefaultGitleaksPolicy())
	assertGeneratedScan(t, scanner, ids, "token=a1b2c3d4;", "token=a1b2c3d4;")
	assertGeneratedScan(t, scanner, ids, "token=a1b2c3d4,")
}

func TestBuildFMGuardrailsRegexRulesFromConfig_Entropy(t *testing.T) {
	t.Parallel()

	const high = "Ab3dEf7hIj9lMn2pQr5tUv8xYz0Kc6Ws"
	low := strings.Repeat("a", len(high))
	for _, tc := range []struct {
		name      string
		include   bool
		threshold float64
		acceptLow bool
	}{
		{"enabled", true, 3.5, false},
		{"disabled", false, 3.5, true},
		{"zero threshold", true, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := DefaultGitleaksPolicy()
			policy.IncludeEntropy = tc.include
			src := tomlsrc.Rule{ID: "entropy-token", Regex: `context=[A-Za-z0-9]+ token=([A-Za-z0-9]{32})(?:\s|$)`, Entropy: tc.threshold}
			scanner, ids := generatedScanner(t, tomlsrc.Config{Rules: []tomlsrc.Rule{src}}, policy)
			// The low-entropy candidate must not borrow entropy from its context.
			text := "context=" + high + " token=" + low
			if tc.acceptLow {
				assertGeneratedScan(t, scanner, ids, text, low)
			} else {
				assertGeneratedScan(t, scanner, ids, text)
			}
			assertGeneratedScan(t, scanner, ids, "context=aaaa token="+high, high)
		})
	}
}

func TestBuildFMGuardrailsRegexRulesFromConfig_SelectedAllowlists(t *testing.T) {
	t.Parallel()

	for _, id := range []string{"aws-access-token", "curl-auth-user", "gcp-api-key", "nuget-config-password", "vault-service-token"} {
		t.Run(id, func(t *testing.T) {
			const excluded = "demo-user:ExamplePass123"
			const accepted = "real-user:Ab3dEf7hIj9lMn2p"
			src := tomlsrc.Rule{
				ID:         id,
				Regex:      `context=[^\n]* token=([^ \n]+)(?:\s|$)`,
				Allowlists: []tomlsrc.Allowlist{{Regexes: []string{`^demo-user:ExamplePass123$`}}, {Regexes: []string{`other-user:Placeholder123`}}},
			}
			scanner, ids := generatedScanner(t, tomlsrc.Config{Rules: []tomlsrc.Rule{src}}, DefaultGitleaksPolicy())
			text := "context=ordinary token=" + excluded + "\ncontext=ordinary token=other-user:Placeholder123\ncontext=" + excluded + " other-user:Placeholder123 token=" + accepted
			if id == "curl-auth-user" {
				// Scan commands separately: the upstream curl override can span lines.
				assertGeneratedScan(t, scanner, ids, `curl -u "`+excluded+`" https://example.test`)
				assertGeneratedScan(t, scanner, ids, `curl -u "other-user:Placeholder123" https://example.test`)
				text = `curl -u "` + accepted + `" https://example.test/other-user:Placeholder123`
			}
			assertGeneratedScan(t, scanner, ids, text, accepted)
		})
	}
	// Allowlists from other rules must not acquire candidate-only semantics.
	src := tomlsrc.Rule{ID: "unselected-token", Regex: `token=([A-Za-z0-9]+)`, Allowlists: []tomlsrc.Allowlist{{Regexes: []string{`.*`}, RegexTarget: "line", Paths: []string{".*"}}}}
	scanner, ids := generatedScanner(t, tomlsrc.Config{Rules: []tomlsrc.Rule{src}}, DefaultGitleaksPolicy())
	assertGeneratedScan(t, scanner, ids, "token=Ab3dEf7hIj9l", "Ab3dEf7hIj9l")
}

func TestBuildFMGuardrailsRegexRulesFromConfig_RejectsUnsupportedSelectedAllowlists(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		allow tomlsrc.Allowlist
	}{
		{"regex target", tomlsrc.Allowlist{RegexTarget: "match"}},
		{"explicit secret target", tomlsrc.Allowlist{RegexTarget: "secret"}},
		{"paths", tomlsrc.Allowlist{Paths: []string{".*"}}},
		{"commits", tomlsrc.Allowlist{Commits: []string{"abc123"}}},
		{"stopwords", tomlsrc.Allowlist{StopWords: []string{"example"}}},
		{"condition", tomlsrc.Allowlist{Condition: "OR"}},
		{"invalid regex", tomlsrc.Allowlist{Regexes: []string{"["}}},
		{"empty regex", tomlsrc.Allowlist{Regexes: []string{""}}},
	}
	for _, id := range []string{"aws-access-token", "curl-auth-user", "gcp-api-key", "nuget-config-password", "vault-service-token"} {
		for _, tc := range cases {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				allow := tc.allow
				if len(allow.Regexes) == 0 {
					allow.Regexes = []string{`^placeholder$`}
				}
				src := tomlsrc.Rule{ID: id, Regex: `token=([A-Za-z0-9]+)`, Allowlists: []tomlsrc.Allowlist{{Regexes: []string{`^safe$`}}, allow}}
				_, _, err := buildFMGuardrailsRegexRulesFromConfig(tomlsrc.Config{Rules: []tomlsrc.Rule{src}}, DefaultGitleaksPolicy())
				if err == nil || !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "allowlist 1") {
					t.Fatalf("expected rule ID and allowlist index in error, got %v", err)
				}
			})
		}
	}
}

func generatedScanner(t *testing.T, cfg tomlsrc.Config, policy Policy) (*sensitive.Scanner, []string) {
	t.Helper()

	out, _, err := buildFMGuardrailsRegexRulesFromConfig(cfg, policy)
	if err != nil {
		t.Fatalf("generate rules: %v", err)
	}
	data, err := MarshalOutput(out)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	_, rules, err := rule.LoadAll(path)
	if err != nil {
		t.Fatalf("load generated rules: %v", err)
	}
	if len(rules) != len(cfg.Rules) {
		t.Fatalf("loaded %d rules, want %d", len(rules), len(cfg.Rules))
	}
	reg, err := registry.Build(rules...)
	if err != nil {
		t.Fatalf("compile generated rules: %v", err)
	}
	ids := make([]string, 0, len(rules))
	for _, rl := range rules {
		ids = append(ids, rl.ID)
	}
	return sensitive.New(reg), ids
}

func assertGeneratedScan(t *testing.T, scanner *sensitive.Scanner, ids []string, text string, want ...string) {
	t.Helper()

	matches, err := scanner.Scan(text, ids)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(matches) != len(want) {
		t.Fatalf("scan %q: got %+v, want values %q", text, matches, want)
	}
	cursor := 0
	for i, value := range want {
		start := strings.Index(text[cursor:], value)
		if start < 0 {
			t.Fatalf("expected value %q absent after offset %d", value, cursor)
		}
		start += cursor
		m := matches[i]
		if m.FullText != value || m.Start != start || m.End != start+len(value) {
			t.Fatalf("match %d: got %+v, want %q at [%d,%d)", i, m, value, start, start+len(value))
		}
		cursor = m.End
	}
}
