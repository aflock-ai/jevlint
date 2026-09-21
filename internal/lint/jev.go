package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	jevEndpoint = "https://api.typesafe.ai/v1/systemone"
	// DefaultModel is the pinned Jev model. Thresholds are tuned per version, so
	// a verdict records which model produced it.
	DefaultModel = "jev-1.13.0"
	jevTimeout   = 20 * time.Second
)

// Client talks to the Jev System One endpoint.
type Client struct {
	key   string
	model string
	http  *http.Client
}

// NewClient builds a client. An empty key is allowed; HasKey reports it, and
// callers should refuse to run semantic checks without one.
func NewClient(model, key string) *Client {
	if model == "" {
		model = DefaultModel
	}
	if key == "" {
		key = ResolveKey()
	}
	return &Client{key: key, model: model, http: &http.Client{Timeout: jevTimeout}}
}

func (c *Client) HasKey() bool  { return c.key != "" }
func (c *Client) Model() string { return c.model }

// ResolveKey mirrors the jev CLI / jade triage lookup: env, then the documented
// file, then the macOS keychain. Viper layers config on top of this in cmd.
func ResolveKey() string {
	if k := strings.TrimSpace(os.Getenv("TYPESAFE_API_KEY")); k != "" {
		return k
	}
	path := strings.TrimSpace(os.Getenv("TYPESAFE_API_KEY_FILE"))
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, ".config", "typesafe", "api_key")
		}
	}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if line := strings.SplitN(strings.TrimSpace(string(b)), "\n", 2)[0]; line != "" {
				return line
			}
		}
	}
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("security", "find-generic-password", "-s", "TYPESAFE_API_KEY", "-w").Output()
		if err == nil {
			if k := strings.TrimSpace(string(out)); k != "" {
				return k
			}
		}
	}
	return ""
}

// askNoul returns (probability, ok, reason). A missing, out-of-range, or
// unreachable answer is (0, false, reason) — never a silent zero.
func (c *Client) askNoul(state map[string]any, qid, question, trueMeans, falseMeans string) (float64, bool, string) {
	if c.key == "" {
		return 0, false, "no API key"
	}
	body, _ := json.Marshal(map[string]any{
		"state": state,
		"model": c.model,
		"questions": map[string]any{
			qid: map[string]any{
				"type":         "noul",
				"instructions": map[string]string{"question": question},
				"criteria":     map[string]string{"true": trueMeans, "false": falseMeans},
			},
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), jevTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, jevEndpoint, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, false, "transport error"
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, false, "read error"
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return 0, false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		Answers map[string]struct {
			Type string   `json:"type"`
			Noul *float64 `json:"noul"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return 0, false, "unparseable reply"
	}
	a, ok := parsed.Answers[qid]
	if !ok || a.Noul == nil || *a.Noul < 0 || *a.Noul > 1 {
		return 0, false, "no usable answer"
	}
	return *a.Noul, true, ""
}

// SemanticChecks are the judgments a schema validator cannot make. context is
// optional; when set it enables the over-scoped check.
func SemanticChecks(p *Policy, c *Client, repoContext string, minProb float64) []Finding {
	var out []Finding
	for stepName, step := range p.Steps {
		for _, att := range step.Attestations {
			for _, rp := range att.RegoPolicies {
				rego := rp.DecodeRego()
				if strings.TrimSpace(rego) == "" {
					continue
				}
				loc := fmt.Sprintf("step %s · %s · %s", stepName, att.Type, rp.Name)

				if pr, ok, reason := c.askNoul(map[string]any{"rego": rego}, "unconditional_deny",
					"Does this Rego module contain a deny rule that fires with no condition constraining the input evidence — an unconditional refusal that no attestation can ever satisfy?",
					"a deny rule sets its message with no guard on the input, so it always fires",
					"every deny rule is guarded by a condition on the input evidence"); !ok {
					out = append(out, Finding{Unknown, "could-not-check", loc,
						"Jev gave no answer (" + reason + ") — this module was not judged.", "", 0})
				} else if pr >= minProb {
					out = append(out, Finding{High, "unconditional-deny", loc,
						fmt.Sprintf("Rego appears to deny unconditionally (p=%.2f) — this rule refuses all evidence.", pr),
						"Guard the deny with a condition on the input, or remove the placeholder rule.", pr})
				}

				if pr, ok, _ := c.askNoul(map[string]any{"rego": rego}, "underspecified",
					"Does this Rego read a field from the input but never compare it, so it admits values it appears to check?",
					"a field is read but never constrained, leaving a hole",
					"every field the decision depends on is compared"); ok && pr >= minProb {
					out = append(out, Finding{Medium, "underspecified-check", loc,
						fmt.Sprintf("Rego may read a field without constraining it (p=%.2f) — it could admit what it looks like it checks.", pr),
						"Compare every field the decision depends on; a field read but not compared is a hole.", pr})
				}
			}
		}
	}
	if repoContext != "" {
		types := p.AttestationTypes()
		loc := fmt.Sprintf("policy · %d attestation types", len(types))
		if pr, ok, reason := c.askNoul(
			map[string]any{"repository": repoContext, "required_attestation_types": types},
			"over_scoped",
			"Given the repository description, does this policy require attestation types the repository cannot realistically produce?",
			"it demands evidence types this repo cannot produce",
			"the required types fit what this repo produces"); !ok {
			out = append(out, Finding{Unknown, "could-not-check", loc,
				"Jev gave no answer (" + reason + ") — over-scoping not judged.", "", 0})
		} else if pr >= minProb {
			out = append(out, Finding{Medium, "over-scoped", loc,
				fmt.Sprintf("Policy may be over-scoped for this repo (p=%.2f): requires %s.", pr, strings.Join(types, ", ")),
				"Require only the attestation types this repository actually produces.", pr})
		}
	}
	return out
}
