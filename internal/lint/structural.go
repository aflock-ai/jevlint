package lint

import (
	"fmt"
	"strings"
	"time"
)

// StructuralChecks are deterministic. They never call Jev and never fail open:
// anything security-critical that can be decided from the document lives here,
// so an outage can never downgrade it to "looks fine".
func StructuralChecks(p *Policy) []Finding {
	var out []Finding

	if len(p.Roots) == 0 {
		out = append(out, Finding{High, "no-roots", "policy",
			"No roots block — nothing anchors the signing certificates.",
			"Add a roots block with the platform Root CA (base64) from the discovery doc.", 0})
	}
	for name, r := range p.Roots {
		if r.Certificate != "" && len(r.Intermediates) == 0 {
			out = append(out, Finding{Low, "no-intermediates", "root " + name,
				"Root has a certificate but no intermediates — a leaf that chains through a Fulcio intermediate will not verify.",
				"If signing is keyless, list the Fulcio CA (base64) in intermediates.", 0})
		}
	}

	if len(p.TimestampAuthorities) == 0 {
		out = append(out, Finding{Medium, "no-tsa", "policy",
			"No timestampauthorities — a signature can only be judged against the cert's own lifetime, not an RFC-3161 time.",
			"Add a timestampauthorities block from discovery signing.tsa_cert_chain_url.", 0})
	}

	out = append(out, expiryChecks(p)...)

	for name, step := range p.Steps {
		loc := "step " + name
		if len(step.Attestations) > 0 && len(step.Functionaries) == 0 {
			out = append(out, Finding{High, "no-functionary", loc,
				"Step requires attestations but names no functionary — nothing is allowed to sign it, so it can never pass.",
				"Add a functionary (a certConstraint or public key) that may sign this step.", 0})
		}
		for _, fn := range step.Functionaries {
			cc := fn.CertConstraint
			if cc == nil {
				continue
			}
			if funcWidens(cc) {
				out = append(out, Finding{High, "wildcard-functionary", loc,
					fmt.Sprintf("Functionary admits any tenant via %s — a signature from any tenant would satisfy this step.", strings.Join(cc.URIs, ", ")),
					"Scope the SPIFFE URI to spiffe://<domain>/tenant/<id>/agent/*.", 0})
			} else if len(cc.URIs) == 0 {
				out = append(out, Finding{Low, "unconstrained-functionary", loc,
					"Functionary certConstraint names no SPIFFE URI to scope identity by.",
					"Add a uris entry pinning the tenant, or use a public key constraint.", 0})
			}
			var empties []string
			for k, v := range map[string][]string{"dnsnames": cc.DNSNames, "emails": cc.Emails, "organizations": cc.Organizations} {
				if v != nil && len(v) == 0 {
					empties = append(empties, k)
				}
			}
			if len(empties) > 0 {
				out = append(out, Finding{Low, "empty-constraints", loc,
					fmt.Sprintf("Empty %s fail closed under --policy-hardening enforce.", strings.Join(empties, "/")),
					`Set the field to ["*"] to admit any, or list the exact values to require.`, 0})
			}
		}
	}

	// Deterministic Rego and secret checks — these run offline so the worst
	// bugs (an unconditional deny, a leaked key) are caught without a Jev key.
	out = append(out, regoDenyChecks(p)...)
	out = append(out, SecretChecks(p)...)
	return out
}

func expiryChecks(p *Policy) []Finding {
	if p.Expires == "" {
		return []Finding{{Medium, "no-expiry", "policy",
			"No expires field — the policy never goes stale on its own.",
			"Set expires to an RFC-3339 timestamp bounding the policy's life.", 0}}
	}
	t, err := time.Parse(time.RFC3339, p.Expires)
	if err != nil {
		return []Finding{{Low, "bad-expiry", "policy",
			"expires is not an RFC-3339 timestamp: " + p.Expires,
			"Use an RFC-3339 timestamp, e.g. 2027-01-01T00:00:00Z.", 0}}
	}
	now := time.Now()
	if t.Before(now) {
		return []Finding{{High, "expired", "policy",
			"Policy expired on " + p.Expires + " — it will be rejected.",
			"Re-sign the policy with a future expires.", 0}}
	}
	if t.Before(now.AddDate(0, 0, 30)) {
		return []Finding{{Medium, "expiring-soon", "policy",
			"Policy expires within 30 days (" + p.Expires + ").",
			"Plan a re-sign before it lapses.", 0}}
	}
	return nil
}
