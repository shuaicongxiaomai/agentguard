// Package agentguard implements the security tools exposed by the AgentGuard MCP
// server: local secret scanning and OSV-backed vulnerability checks.
package agentguard

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

// SecretFinding is one detected secret.
type SecretFinding struct {
	Type   string `json:"type"`
	Masked string `json:"masked"` // the value with the middle redacted
	Line   int    `json:"line"`   // 1-based line number
}

// namedPattern is a high-precision detector for a known credential format.
type namedPattern struct {
	name string
	re   *regexp.Regexp
}

var namedPatterns = []namedPattern{
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"GitHub Personal Access Token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"GitHub Fine-grained Token", regexp.MustCompile(`github_pat_[0-9A-Za-z_]{60,}`)},
	{"Anthropic API Key", regexp.MustCompile(`sk-ant-[0-9A-Za-z_\-]{20,}`)},
	{"OpenAI API Key", regexp.MustCompile(`sk-(?:proj-)?[0-9A-Za-z_\-]{20,}`)},
	{"Stripe Secret Key", regexp.MustCompile(`(?:sk|rk)_live_[0-9A-Za-z]{20,}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`)},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]+`)},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"JSON Web Token", regexp.MustCompile(`eyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}`)},
}

// genericAssignment matches `api_key = "...."`-style assignments; the captured
// value is then entropy-checked to cut false positives.
var genericAssignment = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|client[_-]?secret)\s*[:=]\s*['"]?([0-9A-Za-z_\-/+\.]{16,})['"]?`)

// ScanSecrets scans text for hard-coded credentials and returns the findings,
// sorted by line. Values are masked — the raw secret is never returned.
func ScanSecrets(text string) []SecretFinding {
	starts := lineStarts(text)
	var out []SecretFinding
	seen := map[string]bool{}    // dedupe by type+masked+line
	valueAt := map[string]bool{} // masked+line already reported (by any rule)

	add := func(typ, val string, idx int) {
		f := SecretFinding{Type: typ, Masked: mask(val), Line: indexToLine(starts, idx)}
		key := f.Type + "|" + f.Masked + "|" + itoa(f.Line)
		if !seen[key] {
			seen[key] = true
			valueAt[f.Masked+"|"+itoa(f.Line)] = true
			out = append(out, f)
		}
	}

	// Precise, named detectors first.
	for _, p := range namedPatterns {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			add(p.name, text[loc[0]:loc[1]], loc[0])
		}
	}

	// Generic high-entropy fallback — skip values a named rule already caught.
	for _, m := range genericAssignment.FindAllStringSubmatchIndex(text, -1) {
		val := text[m[4]:m[5]] // m[4]:m[5] is the captured value (group 2)
		if shannonEntropy(val) < 3.5 {
			continue
		}
		if valueAt[mask(val)+"|"+itoa(indexToLine(starts, m[4]))] {
			continue
		}
		add("High-entropy secret", val, m[4])
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

func mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

// lineStarts returns the byte offset at which each line begins.
func lineStarts(text string) []int {
	starts := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// indexToLine maps a byte offset to a 1-based line number.
func indexToLine(starts []int, idx int) int {
	lo, hi := 0, len(starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if starts[mid] <= idx {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
