package lint

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

type jsonRaw = json.RawMessage

func hasCheck(fs []Finding, check string) bool {
	for _, f := range fs {
		if f.Check == check {
			return true
		}
	}
	return false
}

func TestStructural_FlagsWildcardAndMissingTSA(t *testing.T) {
	p := &Policy{
		Roots: map[string]Root{"r": {Certificate: "x"}},
		Steps: map[string]Step{"s": {
			Functionaries: []Functionary{{Type: "root", CertConstraint: &CertConstraint{
				URIs: []string{"spiffe://testifysec.com/*"},
			}}},
			Attestations: []Attestation{{Type: "https://aflock.ai/attestations/git/v0.1"}},
		}},
	}
	fs := StructuralChecks(p)
	for _, want := range []string{"wildcard-functionary", "no-tsa", "no-intermediates"} {
		if !hasCheck(fs, want) {
			t.Errorf("expected a %q finding, got %+v", want, fs)
		}
	}
}

// A pure public-key policy needs no roots and no TSA — flagging them is the
// false positive the docs research caught.
func TestStructural_KeyBasedNeedsNoRoots(t *testing.T) {
	p := &Policy{
		Expires:    "2099-01-01T00:00:00Z",
		PublicKeys: map[string]jsonRaw{"k1": []byte("{}")},
		Steps: map[string]Step{"s": {
			Functionaries: []Functionary{{Type: "publickey", PublicKeyID: "k1"}},
			Attestations:  []Attestation{{Type: "https://aflock.ai/attestations/git/v0.1"}},
		}},
	}
	fs := StructuralChecks(p)
	if hasCheck(fs, "no-roots") || hasCheck(fs, "no-tsa") {
		t.Errorf("a key-based policy must not be flagged for missing roots/tsa, got %+v", fs)
	}
}

// A wildcard hidden behind a tenant-pinned URI must still be caught — the
// short-circuit bug.
func TestFunc_MixedPinnedAndWildcard(t *testing.T) {
	p := &Policy{
		Roots:                map[string]Root{"r": {Certificate: "x", Intermediates: []string{"y"}}},
		TimestampAuthorities: map[string]jsonRaw{"t": []byte("{}")},
		Expires:              "2099-01-01T00:00:00Z",
		Steps: map[string]Step{"s": {
			Functionaries: []Functionary{{Type: "root", CertConstraint: &CertConstraint{
				URIs: []string{"spiffe://d/tenant/x/agent/*", "spiffe://d/*"},
			}}},
			Attestations: []Attestation{{Type: "t"}},
		}},
	}
	if !hasCheck(StructuralChecks(p), "wildcard-functionary") {
		t.Error("an untenanted spiffe wildcard must be caught even beside a tenant-pinned one")
	}
}

func TestFunc_TrustsAnyRoot(t *testing.T) {
	p := &Policy{
		Roots:                map[string]Root{"r": {Certificate: "x", Intermediates: []string{"y"}}},
		TimestampAuthorities: map[string]jsonRaw{"t": []byte("{}")},
		Expires:              "2099-01-01T00:00:00Z",
		Steps: map[string]Step{"s": {
			Functionaries: []Functionary{{Type: "root", CertConstraint: &CertConstraint{
				URIs: []string{"spiffe://d/tenant/x/agent/*"}, Roots: []string{"*"},
			}}},
			Attestations: []Attestation{{Type: "t"}},
		}},
	}
	if !hasCheck(StructuralChecks(p), "trusts-any-root") {
		t.Error(`certConstraint.roots ["*"] must be flagged`)
	}
}

func TestStructural_TenantPinnedIsClean(t *testing.T) {
	p := &Policy{
		Roots:                map[string]Root{"r": {Certificate: "x", Intermediates: []string{"y"}}},
		TimestampAuthorities: map[string]jsonRaw{"t": []byte("{}")},
		Expires:              "2099-01-01T00:00:00Z",
		Steps: map[string]Step{"s": {
			Functionaries: []Functionary{{CertConstraint: &CertConstraint{
				URIs:     []string{"spiffe://testifysec.com/tenant/abc/agent/*"},
				DNSNames: []string{"*"}, Emails: []string{"*"}, Organizations: []string{"*"},
			}}},
			Attestations: []Attestation{{Type: "https://aflock.ai/attestations/git/v0.1"}},
		}},
	}
	if fs := StructuralChecks(p); len(fs) != 0 {
		t.Errorf("expected clean, got %+v", fs)
	}
}

func TestStructural_StepWithoutFunctionary(t *testing.T) {
	p := &Policy{
		Roots:                map[string]Root{"r": {Certificate: "x", Intermediates: []string{"y"}}},
		TimestampAuthorities: map[string]jsonRaw{"t": []byte("{}")},
		Expires:              "2099-01-01T00:00:00Z",
		Steps:                map[string]Step{"s": {Attestations: []Attestation{{Type: "t"}}}},
	}
	if !hasCheck(StructuralChecks(p), "no-functionary") {
		t.Error("a step with attestations but no functionary must be flagged")
	}
}

func TestDiff_DetectsWeakening(t *testing.T) {
	pinned := Step{
		Functionaries: []Functionary{{CertConstraint: &CertConstraint{URIs: []string{"spiffe://d/tenant/x/agent/*"}}}},
		Attestations: []Attestation{
			{Type: "git", RegoPolicies: []RegoPolicy{{Name: "commit"}}},
			{Type: "secretscan"},
		},
	}
	widened := Step{
		Functionaries: []Functionary{{CertConstraint: &CertConstraint{URIs: []string{"spiffe://d/*"}}}},
		Attestations:  []Attestation{{Type: "git"}}, // secretscan dropped, rule dropped
	}
	oldP := &Policy{TimestampAuthorities: map[string]jsonRaw{"t": []byte("{}")}, Steps: map[string]Step{"s": pinned}}
	newP := &Policy{Steps: map[string]Step{"s": widened}}
	fs := DiffPolicies(oldP, newP)
	for _, want := range []string{"functionary-widened", "check-dropped", "rule-dropped", "tsa-removed"} {
		if !hasCheck(fs, want) {
			t.Errorf("expected diff to flag %q, got %+v", want, fs)
		}
	}
}

func TestUnconditionalDeny(t *testing.T) {
	bad := `package p
deny[msg] {
	msg := "rendered without a binding"
}`
	if !hasUnconditionalDeny(bad) {
		t.Error("an unguarded deny must be detected")
	}
	good := `package p
deny[msg] {
	not is_string(input.commithash)
	msg := "missing commithash"
}`
	if hasUnconditionalDeny(good) {
		t.Error("a guarded deny must not be flagged")
	}
	single := `package p
deny[msg] { msg := "always" }`
	if !hasUnconditionalDeny(single) {
		t.Error("a single-line unguarded deny must be detected")
	}
}

func TestSecretInPolicy(t *testing.T) {
	// A private key mistakenly placed where a public cert belongs.
	key := "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n"
	enc := base64.StdEncoding.EncodeToString([]byte(key))
	p := &Policy{Roots: map[string]Root{"r": {Certificate: enc}}}
	if !hasCheck(SecretChecks(p), "secret-in-policy") {
		t.Error("a private key in a root cert must be flagged")
	}
	clean := &Policy{Roots: map[string]Root{"r": {Certificate: base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nMIIabc\n-----END CERTIFICATE-----\n"))}}}
	if hasCheck(SecretChecks(clean), "secret-in-policy") {
		t.Error("a public certificate must not be flagged")
	}
}

func TestFlavor(t *testing.T) {
	cilock := &Policy{Steps: map[string]Step{"s": {Attestations: []Attestation{{Type: "https://aflock.ai/attestations/git/v0.1"}}}}}
	if got := cilock.Flavor(); got != "cilock" {
		t.Errorf("flavor = %q, want cilock", got)
	}
}
