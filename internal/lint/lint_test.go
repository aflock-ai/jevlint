package lint

import (
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
			Functionaries: []Functionary{{CertConstraint: &CertConstraint{
				URIs: []string{"spiffe://testifysec.com/*"}, DNSNames: []string{},
			}}},
			Attestations: []Attestation{{Type: "https://aflock.ai/attestations/git/v0.1"}},
		}},
	}
	fs := StructuralChecks(p)
	for _, want := range []string{"wildcard-functionary", "no-tsa", "no-intermediates", "empty-constraints"} {
		if !hasCheck(fs, want) {
			t.Errorf("expected a %q finding, got %+v", want, fs)
		}
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

func TestFlavor(t *testing.T) {
	cilock := &Policy{Steps: map[string]Step{"s": {Attestations: []Attestation{{Type: "https://aflock.ai/attestations/git/v0.1"}}}}}
	if got := cilock.Flavor(); got != "cilock" {
		t.Errorf("flavor = %q, want cilock", got)
	}
}
