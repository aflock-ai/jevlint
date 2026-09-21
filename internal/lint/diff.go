package lint

import "fmt"

// DiffPolicies flags where NEW is weaker than OLD — the supply-chain move of
// quietly loosening a gate between releases. Every finding is a reduction in
// what the policy proves, mirroring pushgate's weakensRequirements idea.
func DiffPolicies(oldP, newP *Policy) []Finding {
	var out []Finding

	if len(oldP.Roots) > 0 && len(newP.Roots) == 0 {
		out = append(out, Finding{High, "roots-removed", "policy",
			"The new policy has no roots block; the old one did — signing certificates are no longer anchored.",
			"Restore the roots block unless this removal is intended and reviewed.", 0})
	}
	if len(oldP.TimestampAuthorities) > 0 && len(newP.TimestampAuthorities) == 0 {
		out = append(out, Finding{Medium, "tsa-removed", "policy",
			"The new policy dropped timestampauthorities; signatures can no longer be judged against an RFC-3161 time.",
			"Restore the timestampauthorities block.", 0})
	}

	for name, oldStep := range oldP.Steps {
		newStep, ok := newP.Steps[name]
		if !ok {
			out = append(out, Finding{High, "step-removed", "step " + name,
				"The new policy removed this whole step — everything it proved is no longer required.",
				"Restore the step unless the check is intentionally retired.", 0})
			continue
		}
		out = append(out, diffTypes(name, oldStep, newStep)...)
		out = append(out, diffRules(name, oldStep, newStep)...)
		out = append(out, diffFunctionaries(name, oldStep, newStep)...)
	}
	return out
}

func diffTypes(name string, oldStep, newStep Step) []Finding {
	var out []Finding
	newTypes := map[string]bool{}
	for _, att := range newStep.Attestations {
		newTypes[att.Type] = true
	}
	for _, att := range oldStep.Attestations {
		if !newTypes[att.Type] {
			out = append(out, Finding{High, "check-dropped", "step " + name,
				fmt.Sprintf("The new policy no longer requires %s — a check the old one enforced is gone.", att.Type),
				"Restore the attestation type unless dropping this check is intended.", 0})
		}
	}
	return out
}

func diffRules(name string, oldStep, newStep Step) []Finding {
	var out []Finding
	newRules := map[string]bool{}
	for _, att := range newStep.Attestations {
		for _, rp := range att.RegoPolicies {
			newRules[att.Type+"|"+rp.Name] = true
		}
	}
	for _, att := range oldStep.Attestations {
		for _, rp := range att.RegoPolicies {
			if !newRules[att.Type+"|"+rp.Name] {
				out = append(out, Finding{Medium, "rule-dropped", "step " + name + " · " + att.Type,
					fmt.Sprintf("Rego rule %q is gone from the new policy — a constraint was removed.", rp.Name),
					"Confirm the rule was meant to be removed, not lost in a re-render.", 0})
			}
		}
	}
	return out
}

func diffFunctionaries(name string, oldStep, newStep Step) []Finding {
	if anyFuncWidens(newStep) && !anyFuncWidens(oldStep) {
		return []Finding{{High, "functionary-widened", "step " + name,
			"The new policy admits a broader set of signers (a wildcard tenant) than the old one.",
			"Pin the functionary back to a specific /tenant/<id>/.", 0}}
	}
	return nil
}

func anyFuncWidens(step Step) bool {
	for _, fn := range step.Functionaries {
		if funcWidens(fn.CertConstraint) {
			return true
		}
	}
	return false
}
