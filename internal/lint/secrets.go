package lint

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// A policy document carries public certificates and Rego. A private key or an
// API token in one is a leak in a file people share and sign. These patterns
// are chosen for near-zero false positives — definite secrets only.
var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"private key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`)},
	{"AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
}

// SecretChecks scans the policy for embedded secrets: decoded root certificates
// (which must be public), decoded Rego modules, and every other string field.
func SecretChecks(p *Policy) []Finding {
	var sb strings.Builder

	// Decoded root certificates — a PRIVATE KEY here is the classic slip.
	for _, r := range p.Roots {
		if dec, err := base64.StdEncoding.DecodeString(r.Certificate); err == nil {
			sb.Write(dec)
			sb.WriteByte('\n')
		}
		for _, im := range r.Intermediates {
			if dec, err := base64.StdEncoding.DecodeString(im); err == nil {
				sb.Write(dec)
				sb.WriteByte('\n')
			}
		}
	}
	// Decoded Rego modules.
	for _, step := range p.Steps {
		for _, att := range step.Attestations {
			for _, rp := range att.RegoPolicies {
				sb.WriteString(rp.DecodeRego())
				sb.WriteByte('\n')
			}
		}
	}
	// Every remaining string field, via a re-marshal.
	if raw, err := json.Marshal(p); err == nil {
		sb.Write(raw)
	}

	blob := sb.String()
	var out []Finding
	for _, pat := range secretPatterns {
		if pat.re.MatchString(blob) {
			out = append(out, Finding{High, "secret-in-policy", "policy",
				"The policy document embeds what looks like a " + pat.name + " — policies carry only public certificates and Rego.",
				"Remove the secret and rotate it; if it was a root, use the public certificate only.", 0})
		}
	}
	return out
}
