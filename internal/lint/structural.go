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

	// roots and a TSA only matter when the policy verifies via X.509/keyless
	// certificates. A pure public-key policy legitimately has neither, so these
	// are gated to avoid a false positive on key-based policies.
	usesCerts := p.hasCertFunctionary()
	if usesCerts && len(p.Roots) == 0 {
		out = append(out, Finding{High, "no-roots", "policy",
			"A functionary verifies by X.509 certificate, but the policy has no roots — an x509 verifier with no trusted roots cannot verify anything.",
			"Add a roots block with the trusted CA (base64), or switch the functionary to a public key.", 0})
	}
	for name, r := range p.Roots {
		if r.Certificate != "" && len(r.Intermediates) == 0 {
			out = append(out, Finding{Low, "no-intermediates", "root " + name,
				"Root has a certificate but no intermediates — a leaf that chains through an intermediate (e.g. a Fulcio CA) will not verify.",
				"If signing is keyless, list the intermediate CA (base64) in intermediates.", 0})
		}
	}
	if usesCerts && len(p.TimestampAuthorities) == 0 {
		out = append(out, Finding{Low, "no-tsa", "policy",
			"No timestampauthorities. Timestamping is optional in witness, but keyless (short-lived Fulcio) certificates outlive their validity window and need a TSA root to verify after expiry.",
			"If signatures are keyless/timestamped, add a timestampauthorities block from discovery signing.tsa_cert_chain_url.", 0})
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
			// Cert checks apply only to cert-based functionaries; a publickeyid
			// functionary ignores certConstraint entirely.
			if !fn.certBased() {
				continue
			}
			cc := fn.CertConstraint
			if cc == nil {
				continue
			}
			if funcWidens(cc) {
				out = append(out, Finding{High, "wildcard-functionary", loc,
					fmt.Sprintf("A SPIFFE URI constraint (%s) is a wildcard not scoped to a /tenant/<id>/ path — under this trust domain it accepts any tenant's agents.", strings.Join(cc.URIs, ", ")),
					"Scope the SPIFFE URI to spiffe://<trust-domain>/tenant/<id>/agent/*.", 0})
			}
			if trustsAnyRoot(cc) {
				out = append(out, Finding{Medium, "trusts-any-root", loc,
					`Functionary certConstraint.roots is ["*"], which accepts a certificate from ANY configured root.`,
					"List the specific root IDs this step should trust instead of \"*\".", 0})
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
