package lint

import (
	"regexp"
	"strings"
)

var denyOpen = regexp.MustCompile(`^\s*deny\b.*\{`)

// regoDenyChecks deterministically flags a deny rule whose body carries no
// condition on the input — only a message assignment — so it fires on every
// evaluation and no evidence can satisfy it. This is the B9 "rendered without a
// binding" pattern, and catching it here means structural-only mode (no key, no
// egress) catches the single worst policy bug. Jev still covers subtler cases.
func regoDenyChecks(p *Policy) []Finding {
	var out []Finding
	for stepName, step := range p.Steps {
		for _, att := range step.Attestations {
			for _, rp := range att.RegoPolicies {
				if hasUnconditionalDeny(rp.DecodeRego()) {
					out = append(out, Finding{High, "unconditional-deny",
						"step " + stepName + " · " + att.Type + " · " + rp.Name,
						"A deny rule has no condition on the input — it fires on every evaluation, so no attestation can pass.",
						"Guard the deny with a condition on the input, or remove the placeholder rule.", 0})
				}
			}
		}
	}
	return out
}

// hasUnconditionalDeny reports whether any deny block has an empty guard. A body
// line counts as a condition unless it is blank, a comment, a brace, or the
// message assignment itself.
func hasUnconditionalDeny(rego string) bool {
	if strings.TrimSpace(rego) == "" {
		return false
	}
	lines := strings.Split(rego, "\n")
	inDeny, depth, conds := false, 0, 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if !inDeny {
			if denyOpen.MatchString(raw) {
				inDeny, depth, conds = true, strings.Count(line, "{")-strings.Count(line, "}"), 0
				if depth <= 0 { // single-line deny: `deny[msg] { msg := "x" }`
					if !bodyIsCondition(afterBrace(line)) {
						return true
					}
					inDeny = false
				}
			}
			continue
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			if conds == 0 {
				return true
			}
			inDeny = false
			continue
		}
		if bodyIsCondition(line) {
			conds++
		}
	}
	return false
}

// bodyIsCondition reports whether a body line constrains the decision. Blank,
// comment, brace-only, and the msg assignment are not conditions.
func bodyIsCondition(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" || line == "{" || line == "}" || strings.HasPrefix(line, "#") {
		return false
	}
	if msgAssign.MatchString(line) {
		return false
	}
	return true
}

var msgAssign = regexp.MustCompile(`^msg\s*:?=`)

func afterBrace(line string) string {
	i := strings.Index(line, "{")
	j := strings.LastIndex(line, "}")
	if i < 0 || j <= i {
		return ""
	}
	return line[i+1 : j]
}
