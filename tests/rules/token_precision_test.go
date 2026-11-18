// Modified in this fork: exercise token precision through the real configured scanner.
package rules_test

import (
	"encoding/base64"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/registry"
	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/scanners/sensitive"
)

const precisionLiteral = "AbCdEfGhIjKlMnOpQrStUvWxYzABCDEF"
const precisionHex = "0123456789abcdef0123456789abcdef"

func syntheticBedrockToken() string {
	signedURL := "bedrock.amazonaws.com/?Action=InvokeModel&Version=2023-09-30&X-Amz-Credential=SYNTHETIC%2F20261109%2Fus-east-1%2Fbedrock%2Faws4_request&X-Amz-Signature=" + precisionHex + precisionHex
	return "bedrock-api-key-" + base64.StdEncoding.EncodeToString([]byte(signedURL))
}

// These expectations describe consumer-visible semantic spans, not regex-derived
// examples. All credential/API/token rules participate, including overlaps.
func TestTokenPrecisionRealConfig(t *testing.T) {
	t.Parallel()
	_, rulesByID := loadRealConfigScanner(t)
	reg := registry.NewRegistry()
	var ids []string
	for id, rl := range rulesByID {
		if rl.DataType >= 1 && rl.DataType <= 3 {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		reg.Register(rulesByID[id])
	}
	scanners := []*sensitive.Scanner{
		sensitive.New(reg, sensitive.WithKeywordPrefilter(false)),
		sensitive.New(reg, sensitive.WithKeywordPrefilter(true)),
	}

	type precisionCase struct {
		name   string
		input  string
		values []string
	}
	cases := []precisionCase{
		{name: "Java class", input: "public class ArbitraryPaymentThresholdLoadingTest {}"},
		{name: "Java DTO with digit", input: "CustomerAdjustmentListInfo1Result"},
		{name: "Java method with digits", input: "convertConflictTo422IfConflictCode"},
		{name: "unknown bare mixed token", input: precisionLiteral + "qRsTuVwX"},
		{name: "bare MD5", input: precisionHex},
		{name: "bare SHA1", input: precisionHex + "89abcdef"},
		{name: "unrelated Twilio hash", input: "Twilio migration\nchecksum = " + precisionHex},
		{name: "unrelated Sourcegraph hash", input: "sourcegraph migration\ncommit " + precisionHex + "89abcdef"},
		{name: "generic key JSON", input: `{"key":"` + precisionLiteral + `"}`},
		{name: "nested bare key", input: `{"request":{"api":{"key":"` + precisionLiteral + `"}}}`},
		{name: "non-secret field", input: "api_key_name=ArbitraryPaymentThresholdLoadingTest"},
		{name: "unrelated Jira field", input: "jira_issue_id=AbCdEfGhIjKlMnOpQrSt1234"},
		{name: "Confluence page", input: "Confluence page: AbCdEfGhIjKlMnOpQrSt1234"},
		{name: "one-time migration", input: "one-time migration BFAM12345678"},
		{name: "OTP dashed date", input: "otp: 2026-11-09"},
		{name: "OTP slashed date", input: "otp: 2026/11/09"},
		{name: "OTP dotted date", input: "otp: 2026.11.09"},
		{name: "OTP too long", input: "otp: 123456789"},
		{name: "OTP unrelated intervening words", input: "otp was sent in issue 847593"},
		{name: "prose without separator", input: "Токен " + precisionLiteral + " используется"},
		{name: "prose distant secret", input: "токен перестал работать: " + precisionLiteral},
		{name: "assignment double quoted", input: `api_key="` + precisionLiteral + `",`, values: []string{precisionLiteral}},
		{name: "assignment single quoted", input: `api-key='` + precisionLiteral + `';`, values: []string{precisionLiteral}},
		{name: "assignment bare", input: "apiKey=" + precisionLiteral, values: []string{precisionLiteral}},
		{name: "nested explicit API key", input: `{"request":{"api_key":"` + precisionLiteral + `"}}`, values: []string{precisionLiteral}},
		{name: "Russian prose", input: "токен: " + precisionLiteral, values: []string{precisionLiteral}},
		{name: "English prose", input: "API key = '" + precisionLiteral + "'", values: []string{precisionLiteral}},
		{name: "recovery code", input: "код восстановления 847593 отправлен", values: []string{"847593"}},
		{name: "OTP eight digit date shaped code", input: "otp=20261109", values: []string{"20261109"}},
		{name: "OTP four digits", input: "one-time code: 8475", values: []string{"8475"}},
		{name: "Bearer", input: "Authorization: Bearer " + precisionLiteral, values: []string{precisionLiteral}},
		{name: "Basic", input: "Authorization: Basic dGVzdGluZw==", values: []string{"dGVzdGluZw=="}},
		{name: "curl header", input: `curl -H "Authorization: Bearer ` + precisionLiteral + `" https://example.test`, values: []string{precisionLiteral}},
		{name: "JSON header", input: `{"Authorization":"Bearer ` + precisionLiteral + `"}`, values: []string{precisionLiteral}},
		{name: "false header prefix", input: "NotX-API-Key: " + precisionLiteral},
		{name: "class mentioning header", input: "class NotAuthorization: Bearer " + precisionLiteral},
		{name: "header next line", input: "Authorization:\nBearer " + precisionLiteral},
		{name: "header scheme next line", input: "Authorization: Bearer\n" + precisionLiteral},
		{name: "API key header next line", input: "X-API-Key:\n" + precisionLiteral},
		{name: "Twilio contextual", input: `TWILIO_AUTH_TOKEN="` + precisionHex + `"`, values: []string{precisionHex}},
		{name: "Sourcegraph legacy contextual", input: "sourcegraph_token=" + precisionHex + "89abcdef", values: []string{precisionHex + "89abcdef"}},
		{name: "Sourcegraph modern", input: "sgp_" + precisionHex + "89abcdef", values: []string{"sgp_" + precisionHex + "89abcdef"}},
		{name: "Sourcegraph modern local", input: "sgp_local_" + precisionHex + "89abcdef", values: []string{"sgp_local_" + precisionHex + "89abcdef"}},
		{name: "Sourcegraph modern deployment", input: "sgp_0123456789abcdef_" + precisionHex + "89abcdef", values: []string{"sgp_0123456789abcdef_" + precisionHex + "89abcdef"}},
		{name: "Jira legacy", input: `jira_api_token="AbCdEfGhIjKlMnOpQrSt1234"`, values: []string{"AbCdEfGhIjKlMnOpQrSt1234"}},
		{name: "Atlassian modern", input: "ATATT3" + strings.Repeat(precisionLiteral, 6)[:186], values: []string{"ATATT3" + strings.Repeat(precisionLiteral, 6)[:186]}},
		{name: "GitHub standalone", input: "ghp_" + precisionLiteral + "7890", values: []string{"ghp_" + precisionLiteral + "7890"}},
		{name: "npm standalone", input: "npm_" + precisionLiteral + "7890", values: []string{"npm_" + precisionLiteral + "7890"}},
		{name: "Anthropic standalone", input: "sk-ant-api03-" + strings.Repeat(precisionLiteral, 3)[:93] + "AA", values: []string{"sk-ant-api03-" + strings.Repeat(precisionLiteral, 3)[:93] + "AA"}},
		{name: "Stripe standalone", input: "sk_live_" + strings.Repeat(precisionLiteral, 2), values: []string{"sk_live_" + strings.Repeat(precisionLiteral, 2)}},
		{name: "Mapbox secret contextual", input: "mapbox_token=sk." + precisionLiteral + "." + precisionLiteral, values: []string{"sk." + precisionLiteral + "." + precisionLiteral}},
		{name: "Mapbox temporary contextual", input: "mapbox_access_token=tk." + precisionLiteral + "." + precisionLiteral, values: []string{"tk." + precisionLiteral + "." + precisionLiteral}},
		{name: "Mapbox unknown bare secret", input: "sk." + precisionLiteral + "." + precisionLiteral},
		{name: "Mapbox empty segment", input: "mapbox_token=sk.." + precisionLiteral},
		{name: "Vault legacy allowlist", input: "s.abcdefghijklmnopqrstuvwx"},
		{name: "Vault legacy secret", input: "s.AbCdEfGhIjKlMnOpQrSt1234", values: []string{"s.AbCdEfGhIjKlMnOpQrSt1234"}},
		{name: "Vault service", input: "hvs." + strings.Repeat(precisionLiteral, 3), values: []string{"hvs." + strings.Repeat(precisionLiteral, 3)}},
		{name: "Vault batch", input: "hvb." + strings.Repeat(precisionLiteral, 5), values: []string{"hvb." + strings.Repeat(precisionLiteral, 5)}},
		{name: "Bedrock full signed value", input: `bedrock credential "` + syntheticBedrockToken() + `";`, values: []string{syntheticBedrockToken()}},
		{name: "Bedrock host prefix only", input: "bedrock-api-key-" + base64.StdEncoding.EncodeToString([]byte("bedrock.amazonaws.com"))},
		{name: "OAuth client ID neighbor", input: `{"client_id":"` + precisionHex + `","client_secret":"` + precisionLiteral + `"}`, values: []string{precisionLiteral}},
		{name: "adjacent assignments", input: "token=" + precisionLiteral + " token=" + precisionHex, values: []string{precisionLiteral, precisionHex}},
		{name: "adjacent JSON literals", input: `{"token":"` + precisionLiteral + `","api_key":"` + precisionHex + `"}`, values: []string{precisionLiteral, precisionHex}},
		{name: "generic maximum bare length", input: "api_key=" + strings.Repeat("Z", 512), values: []string{strings.Repeat("Z", 512)}},
		{name: "generic maximum quoted length", input: `api_key="` + strings.Repeat("Z", 512) + `"`, values: []string{strings.Repeat("Z", 512)}},
		{name: "generic minimum length", input: "token=AbCdEfGhIjKlMnOp", values: []string{"AbCdEfGhIjKlMnOp"}},
		{name: "generic token alphabet", input: `token="AbCdEfGh._~+/=-XYZ"`, values: []string{"AbCdEfGh._~+/=-XYZ"}},
		{name: "prose quoted punctuation", input: `токен: '` + precisionLiteral + `'; готово`, values: []string{precisionLiteral}},
		{name: "Markdown assignment", input: "(api_key=" + precisionLiteral + ")", values: []string{precisionLiteral}},
		{name: "Markdown header", input: "Authorization: Bearer " + precisionLiteral + ")", values: []string{precisionLiteral}},
		{name: "prose overlong", input: "токен: " + strings.Repeat("Z", 513)},
		{name: "prose newline", input: "токен:\n" + precisionLiteral},
		{name: "OTP zero separated dates", input: "recovery code: 20261109-01"},
		{name: "OAuth query secret", input: "https://auth.example.test/?client_id=public&client_secret=" + precisionLiteral, values: []string{precisionLiteral}},
		{name: "generic overlong bare", input: "api_key=" + strings.Repeat("Z", 513)},
		{name: "generic overlong quoted", input: `api_key="` + strings.Repeat("Z", 513) + `"`},
		{name: "generic too short", input: "api_key=AbCdEfGhIjKlMnO"},
		{name: "assignment newline", input: "api_key=\n" + precisionLiteral},
	}

	for _, label := range []string{"api_key", "api-key", "apiKey", "access_token", "access-token", "accessToken", "refresh_token", "refresh-token", "refreshToken", "id_token", "id-token", "idToken", "client_secret", "client-secret", "clientSecret", "auth_token", "auth-token", "authToken", "token"} {
		cases = append(cases, precisionCase{name: "secret field " + label, input: label + "=" + precisionLiteral, values: []string{precisionLiteral}})
	}
	for _, label := range []string{"key", "secret", "access", "pk", "token_name", "mytoken", "client_id", "NotX-API-Key", "not-api_key", "config.api_key", "not-token"} {
		cases = append(cases, precisionCase{name: "ordinary field " + label, input: label + "=" + precisionLiteral})
	}
	for _, label := range []string{"токен", "токен доступа", "API ключ", "API-ключ", "ключ API", "API key", "access token", "refresh token", "client secret"} {
		cases = append(cases, precisionCase{name: "prose label " + label, input: label + ": " + precisionLiteral, values: []string{precisionLiteral}})
	}
	for _, label := range []string{"otp", "one-time code", "recovery code", "код восстановления", "код подтверждения", "код активации", "код из смс", "смс с кодом"} {
		cases = append(cases, precisionCase{name: "OTP label " + label, input: label + " 847593", values: []string{"847593"}})
	}

	// A skipped reference must not suppress a real secret elsewhere in the text.
	for _, literal := range []string{"YOUR_ACCESS_TOKEN", "YOUR_API_KEY", "YOUR_TOKEN", "REPLACE_ME", "CHANGEME", "EXAMPLE_TOKEN", "EXAMPLE_KEY", "your_access_token", `System.getenv("TOKEN")`, `os.getenv("TOKEN")`, `os.environ["TOKEN"]`, "process.env", "process.env.ACCESS_TOKEN", "${ACCESS_TOKEN}", "$ACCESS_TOKEN", "{{ACCESS_TOKEN}}", "<ACCESS_TOKEN>"} {
		for _, context := range []string{"access_token=", "токен: ", "Authorization: Bearer ", "X-API-Key: ", "https://auth.example.test/?access_token="} {
			cases = append(cases, precisionCase{name: "reference " + context + literal, input: context + literal + "\napi_key=" + precisionLiteral, values: []string{precisionLiteral}})
		}
		for _, field := range []string{"api_key", "access_token"} {
			cases = append(cases, precisionCase{name: "quoted reference " + field + literal, input: `{"` + field + `":"` + literal + `"}` + "\napi_key=" + precisionLiteral, values: []string{precisionLiteral}})
		}
		for _, header := range []string{"Authorization: Bearer ", "X-API-Key: "} {
			for _, quote := range []string{`"`, `'`} {
				if strings.Contains(literal, quote) {
					continue
				}
				input := "curl -H " + quote + header + literal + quote + " https://example.test\napi_key=" + precisionLiteral
				cases = append(cases, precisionCase{name: "curl reference " + quote + header + literal, input: input, values: []string{precisionLiteral}})
			}
		}
	}

	publicValues := []string{
		"pk." + strings.ToLower(precisionLiteral) + "." + strings.ToUpper(precisionLiteral),
		"test_pub_" + precisionHex[:31], "live_pub_" + precisionHex[:31],
		"FLWPUBK_TEST-" + precisionHex + "-X", "FLWPUBK_LIVE-" + precisionHex + "-X",
		"pubkey-" + precisionHex,
	}
	for _, public := range publicValues {
		for _, context := range []string{"", "api_key=", "Authorization: Bearer ", "X-API-Key: ", "https://auth.example.test/?access_token="} {
			cases = append(cases, precisionCase{name: "public " + context + public, input: context + public + "\napi_key=" + precisionLiteral, values: []string{precisionLiteral}})
		}
		for _, field := range []string{"api_key", "access_token", "client_secret"} {
			cases = append(cases, precisionCase{name: "quoted public " + field + public, input: `{"` + field + `":"` + public + `"}` + "\napi_key=" + precisionLiteral, values: []string{precisionLiteral}})
		}
		for _, header := range []string{"Authorization: Bearer ", "X-API-Key: "} {
			for _, quote := range []string{`"`, `'`} {
				input := "curl -H " + quote + header + public + quote + " https://example.test\napi_key=" + precisionLiteral
				cases = append(cases, precisionCase{name: "curl public " + quote + header + public, input: input, values: []string{precisionLiteral}})
			}
		}
	}
	for _, input := range []string{
		"adobe_client_id=" + precisionHex,
		"asana_client_id=1234567890123456",
		"bitbucket_client_id=" + precisionHex,
		"discord_client_id=123456789012345678",
		"linkedin_client_id=AbCdEfGhIjKlMn",
		"looker_client_id=AbCdEfGhIjKlMnOpQrSt",
		"messagebird_client_id=12345678-90ab-cdef-1234-567890abcdef",
		"plaid_client_id=AbCdEfGhIjKlMnOpQrSt1234",
	} {
		cases = append(cases, precisionCase{name: "public OAuth ID " + input, input: input})
	}
	// Keep the secret counterparts of removed public formats observable.
	for _, tt := range realConfigRuleCases() {
		switch tt.ruleID {
		case "api_keys.lob-api-key.gl", "access_tokens.flutterwave-secret-key.gl", "access_tokens.flutterwave-encryption-key.gl", "api_keys.mailgun-private-api-token.gl", "access_tokens.mailgun-signing-key.gl", "api_keys.new-relic-browser-api-token.gl":
			cases = append(cases, precisionCase{name: "retained secret " + tt.name, input: tt.input, values: []string{tt.wantFullText}})
		}
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var baseline []sensitive.Match
			for mode, scanner := range scanners {
				got, err := scanner.Scan(tt.input, ids)
				if err != nil {
					t.Fatalf("prefilter=%t: Scan: %v", mode == 1, err)
				}
				if len(got) != len(tt.values) {
					t.Fatalf("prefilter=%t: matches=%+v, want values=%q; input=%q", mode == 1, got, tt.values, tt.input)
				}
				cursor := 0
				for i, value := range tt.values {
					rel := strings.Index(tt.input[cursor:], value)
					if rel < 0 {
						t.Fatalf("invalid fixture: missing value %q", value)
					}
					start := cursor + rel
					end := start + len(value)
					if got[i].Start != start || got[i].End != end || got[i].FullText != value {
						t.Fatalf("prefilter=%t: match=%+v, want [%d:%d] %q", mode == 1, got[i], start, end, value)
					}
					if got[i].Placeholder == "" || got[i].DataType < 1 || got[i].DataType > 3 {
						t.Fatalf("invalid semantic match metadata: %+v", got[i])
					}
					cursor = end
				}
				if mode == 0 {
					baseline = got
				} else if !reflect.DeepEqual(baseline, got) {
					t.Fatalf("keyword prefilter changed exact matches: off=%+v on=%+v", baseline, got)
				}
			}
		})
	}
}
