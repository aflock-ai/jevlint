// Package lint parses a witness/cilock/pushgate policy and checks it for
// meaning: unconditional denials, wildcard functionaries, missing trust
// anchors, and — between two versions — silent weakening.
package lint

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
)

// Policy is a witness policy document — the shape shared by witness, cilock and
// pushgate. Every field is optional so a malformed policy still lints.
type Policy struct {
	Expires              string                     `json:"expires"`
	Roots                map[string]Root            `json:"roots"`
	TimestampAuthorities map[string]json.RawMessage `json:"timestampauthorities"`
	Steps                map[string]Step            `json:"steps"`
}

type Root struct {
	Certificate   string   `json:"certificate"`
	Intermediates []string `json:"intermediates"`
}

type Step struct {
	Name          string        `json:"name"`
	Functionaries []Functionary `json:"functionaries"`
	Attestations  []Attestation `json:"attestations"`
}

type Functionary struct {
	Type           string          `json:"type"`
	PublicKeyID    string          `json:"publickeyid"`
	CertConstraint *CertConstraint `json:"certConstraint"`
}

type CertConstraint struct {
	CommonName    string   `json:"commonname"`
	DNSNames      []string `json:"dnsnames"`
	Emails        []string `json:"emails"`
	Organizations []string `json:"organizations"`
	URIs          []string `json:"uris"`
	Roots         []string `json:"roots"`
}

type Attestation struct {
	Type         string       `json:"type"`
	RegoPolicies []RegoPolicy `json:"regopolicies"`
}

type RegoPolicy struct {
	Name   string `json:"name"`
	Module string `json:"module"`
}

// LoadPolicy reads and decodes a policy JSON file.
func LoadPolicy(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// DecodeRego returns the module's Rego source, base64-decoded.
func (rp RegoPolicy) DecodeRego() string {
	dec, err := base64.StdEncoding.DecodeString(rp.Module)
	if err != nil {
		return ""
	}
	return string(dec)
}

// AttestationTypes lists the distinct predicate types the policy requires.
func (p *Policy) AttestationTypes() []string {
	var out []string
	seen := map[string]bool{}
	for _, step := range p.Steps {
		for _, att := range step.Attestations {
			if att.Type != "" && !seen[att.Type] {
				seen[att.Type] = true
				out = append(out, att.Type)
			}
		}
	}
	return out
}

// Flavor is best-effort: witness | cilock | pushgate. --type overrides it.
func (p *Policy) Flavor() string {
	for _, step := range p.Steps {
		for _, att := range step.Attestations {
			for _, rp := range att.RegoPolicies {
				if strings.Contains(rp.DecodeRego(), "package pushgate.") {
					return "pushgate"
				}
			}
			if strings.Contains(att.Type, "aflock.ai") {
				return "cilock"
			}
		}
	}
	return "witness"
}

func wildcardURI(uri string) bool {
	u := strings.TrimRight(uri, "/")
	return uri == "*" || strings.HasSuffix(u, "/*")
}

func tenantPinned(uris []string) bool {
	for _, u := range uris {
		if strings.Contains(u, "/tenant/") {
			return true
		}
	}
	return false
}

// funcWidens reports whether a functionary admits any tenant via a wildcard not
// scoped to a specific /tenant/<id>/ path.
func funcWidens(cc *CertConstraint) bool {
	if cc == nil {
		return false
	}
	if tenantPinned(cc.URIs) {
		return false
	}
	for _, u := range cc.URIs {
		if wildcardURI(u) {
			return true
		}
	}
	return false
}
