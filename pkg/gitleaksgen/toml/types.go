package toml

// Config is a subset of gitleaks TOML schema required for guardrails import.
type Config struct {
	Title string `toml:"title"`
	Rules []Rule `toml:"rules"`
}

// Rule describes one gitleaks detection rule.
type Rule struct {
	ID          string      `toml:"id"`
	Description string      `toml:"description"`
	Regex       string      `toml:"regex"`
	SecretGroup int         `toml:"secretGroup"`
	Keywords    []string    `toml:"keywords"`
	Entropy     float64     `toml:"entropy"`
	Allowlists  []Allowlist `toml:"allowlists"`
}

// Allowlist retains scope metadata so unsupported semantics cannot be silently lost.
type Allowlist struct {
	Regexes     []string `toml:"regexes"`
	RegexTarget string   `toml:"regexTarget"`
	Paths       []string `toml:"paths"`
	Commits     []string `toml:"commits"`
	StopWords   []string `toml:"stopwords"`
	Condition   string   `toml:"condition"`
}
