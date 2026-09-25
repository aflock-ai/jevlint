package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	jevEndpoint = "https://api.typesafe.ai/v1/systemone"
	// DefaultModel is the pinned Jev model. Thresholds are tuned per version, so
	// a verdict records which model produced it.
	DefaultModel = "jev-1.13.0"
	jevTimeout   = 20 * time.Second

	// DefaultBatchSize is how many Rego modules share one Jev request. It is 1:
	// each module gets its own request carrying BOTH its questions — the pattern
	// DeepEval uses (many questions over ONE shared state). MEASURED on a
	// 12-module policy: merging several modules into one request left
	// unconditional-deny untouched (true positives 0.94–0.98 at every size) but
	// SUPPRESSED underspecified-check — true positives fell from 0.72–0.92 to
	// 0.53–0.76 at 8 per request and to 0.26 at 16, missing 3–4 of 4 at 0.70.
	// Speed comes from DefaultConcurrency instead, which changes nothing Jev sees.
	DefaultBatchSize = 1
	// DefaultConcurrency is how many requests are in flight at once. An earlier
	// Jev issue-triage integration saw ~24% of batches fail at 32 workers; stay
	// well under that and retry.
	DefaultConcurrency = 6
	// maxBatchBytes bounds the Rego text in one request so a batch stays well
	// inside Jev's context window (a 25-item batch in that integration was
	// ~13k tokens).
	maxBatchBytes = 24 << 10
	// maxQuestions is the per-request question ceiling (rookery ai_jev.go).
	maxQuestions = 128
)

// Client talks to the Jev System One endpoint and counts what it spends. It is
// safe for concurrent use.
type Client struct {
	key        string
	model      string
	endpoint   string
	http       *http.Client
	retryDelay time.Duration
	requests   atomic.Int64
	questions  atomic.Int64
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
	return &Client{key: key, model: model, endpoint: jevEndpoint, retryDelay: time.Second,
		http: &http.Client{Timeout: jevTimeout}}
}

func (c *Client) HasKey() bool   { return c.key != "" }
func (c *Client) Model() string  { return c.model }
func (c *Client) Requests() int  { return int(c.requests.Load()) }
func (c *Client) Questions() int { return int(c.questions.Load()) }

// ResolveKey mirrors the jev CLI's lookup: env, then the documented
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

// noulQ is one yes/no question inside a request.
type noulQ struct {
	id, question, trueMeans, falseMeans string
}

// jevErr is a request that produced no answers at all. The flags decide what a
// caller may do next: an auth failure is final, an oversize batch is split.
type jevErr struct {
	reason   string
	auth     bool // 401/403 or no key: retrying or splitting cannot help
	tooLarge bool // over the context window: splitting can help
}

// askBatch sends ONE request carrying many noul questions over one shared
// state. It returns every usable answer by question id; a question with no
// usable answer is simply absent, and the caller reports it. A missing,
// out-of-range, or non-finite value is never a silent zero.
func (c *Client) askBatch(state map[string]any, qs []noulQ) (map[string]float64, *jevErr) {
	if c.key == "" {
		return nil, &jevErr{reason: "no API key", auth: true}
	}
	questions := make(map[string]any, len(qs))
	for _, q := range qs {
		questions[q.id] = map[string]any{
			"type":         "noul",
			"instructions": map[string]string{"question": q.question},
			"criteria":     map[string]string{"true": q.trueMeans, "false": q.falseMeans},
		}
	}
	body, _ := json.Marshal(map[string]any{"state": state, "model": c.model, "questions": questions})
	c.requests.Add(1)
	c.questions.Add(int64(len(qs)))

	ctx, cancel := context.WithTimeout(context.Background(), jevTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &jevErr{reason: "transport error"}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &jevErr{reason: "read error"}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &jevErr{reason: fmt.Sprintf("HTTP %d", resp.StatusCode), auth: true}
	case resp.StatusCode == http.StatusRequestEntityTooLarge ||
		(resp.StatusCode == http.StatusBadRequest && bytes.Contains(raw, []byte("max_tokens"))):
		return nil, &jevErr{reason: "too large for one Jev request", tooLarge: true}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, &jevErr{reason: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	var parsed struct {
		Answers map[string]struct {
			Noul *float64 `json:"noul"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, &jevErr{reason: "unparseable reply"}
	}
	out := make(map[string]float64, len(parsed.Answers))
	for id, a := range parsed.Answers {
		if a.Noul == nil || math.IsNaN(*a.Noul) || *a.Noul < 0 || *a.Noul > 1 {
			continue
		}
		out[id] = *a.Noul
	}
	if len(out) == 0 {
		return nil, &jevErr{reason: "reply carried no answers"}
	}
	return out, nil
}

// askNoul is askBatch for a single question.
func (c *Client) askNoul(state map[string]any, qid, question, trueMeans, falseMeans string) (float64, bool, string) {
	ans, err := c.askBatch(state, []noulQ{{qid, question, trueMeans, falseMeans}})
	if err != nil {
		return 0, false, err.reason
	}
	p, ok := ans[qid]
	if !ok {
		return 0, false, "no usable answer"
	}
	return p, true, ""
}

// regoItem is one Rego module, addressed in a batch by its own NAMED top-level
// field. An earlier Jev triage integration measured an array layout
// contaminating answers at K>=16
// (one true positive smeared 0.97 onto unrelated neighbours); named fields
// were clean up to K=25. Do not turn this into an array.
type regoItem struct {
	field string // module_00, module_01 …
	loc   string
	rego  string
}

// regoKind is one question asked of every module. single is the exact wording
// the pre-batching client sent for a lone module; question names a field and is
// used only when several modules share a request.
type regoKind struct {
	name                  string
	single                string
	question              func(field string) string
	trueMeans, falseMeans string
}

var regoKinds = []regoKind{
	{
		name:   "unconditional_deny",
		single: "Does this Rego module contain a deny rule that fires with no condition constraining the input evidence — an unconditional refusal that no attestation can ever satisfy?",
		question: func(f string) string {
			return "Does the Rego module in field `" + f + "` contain a deny rule that fires with no condition constraining the input evidence — an unconditional refusal that no attestation can ever satisfy?"
		},
		trueMeans:  "a deny rule sets its message with no guard on the input, so it always fires",
		falseMeans: "every deny rule is guarded by a condition on the input evidence",
	},
	{
		name:   "underspecified",
		single: "Is there a value taken from `input` that is assigned to a variable or rule but never used in any condition of a deny rule, so the policy's decision ignores it?",
		question: func(f string) string {
			return "In the Rego module in field `" + f + "`, is there a value taken from `input` that is assigned to a variable or rule but never used in any condition of a deny rule, so the policy's decision ignores it?"
		},
		trueMeans:  "some input value is read and then ignored by every deny rule",
		falseMeans: "every input value that is read is used in a deny condition",
	},
}

func qid(field, kind string) string { return field + "__" + kind }

// regoItems collects every non-empty module in a DETERMINISTIC order. p.Steps is
// a map, so ranging it directly would change batch composition run to run.
func regoItems(p *Policy) []regoItem {
	var items []regoItem
	for stepName, step := range p.Steps {
		for _, att := range step.Attestations {
			for _, rp := range att.RegoPolicies {
				rego := rp.DecodeRego()
				if strings.TrimSpace(rego) == "" {
					continue
				}
				items = append(items, regoItem{
					loc:  fmt.Sprintf("step %s · %s · %s", stepName, att.Type, rp.Name),
					rego: rego,
				})
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].loc < items[j].loc })
	for i := range items {
		items[i].field = fmt.Sprintf("module_%02d", i)
	}
	return items
}

// chunkItems packs modules into batches of at most size, bounded by the Rego
// byte budget and the per-request question ceiling. A module bigger than the
// budget travels alone.
func chunkItems(items []regoItem, size, maxBytes, perItem, maxQ int) [][]regoItem {
	if size < 1 {
		size = 1
	}
	var out [][]regoItem
	var cur []regoItem
	curBytes := 0
	for _, it := range items {
		n := len(it.rego)
		if len(cur) > 0 && (len(cur) >= size || curBytes+n > maxBytes || (len(cur)+1)*perItem > maxQ) {
			out = append(out, cur)
			cur, curBytes = nil, 0
		}
		cur = append(cur, it)
		curBytes += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// buildRequest lays out one request. A LONE module is sent exactly as the
// pre-batching client sent it — state {"rego": …}, the original wording, the
// original question ids. MEASURED: a lone module behind an opaque field name
// (`module_06`) lost signal against that shape (a true unconditional deny fell
// from 0.86 to 0.64–0.67 and was missed at 0.70), and every single-module
// policy is a batch of one whatever --batch-size says. Named fields are used
// only when several modules genuinely share a request.
//
// canon[i] is the stable id that qs[i]'s answer is filed under, whatever id it
// travelled with.
func buildRequest(batch []regoItem) (state map[string]any, qs []noulQ, canon []string) {
	state = make(map[string]any, len(batch))
	if len(batch) == 1 {
		it := batch[0]
		state["rego"] = it.rego
		for _, k := range regoKinds {
			qs = append(qs, noulQ{k.name, k.single, k.trueMeans, k.falseMeans})
			canon = append(canon, qid(it.field, k.name))
		}
		return state, qs, canon
	}
	for _, it := range batch {
		state[it.field] = it.rego
		for _, k := range regoKinds {
			id := qid(it.field, k.name)
			qs = append(qs, noulQ{id, k.question(it.field), k.trueMeans, k.falseMeans})
			canon = append(canon, id)
		}
	}
	return state, qs, canon
}

// runBatch asks every question about every module in batch in one request.
// A request that fails is RETRIED once, never recorded as judged; an oversize
// or still-failing batch is split in half so one bad module cannot sink the
// rest. An auth failure is final — splitting would only multiply the refusals.
func (c *Client) runBatch(batch []regoItem, retried bool) (map[string]float64, map[string]string) {
	state, qs, canon := buildRequest(batch)
	ans, err := c.askBatch(state, qs)
	if err == nil {
		out := make(map[string]float64, len(qs))
		failed := map[string]string{}
		for i, q := range qs {
			if v, ok := ans[q.id]; ok {
				out[canon[i]] = v
			} else {
				failed[canon[i]] = "no usable answer"
			}
		}
		return out, failed
	}
	failAll := func() map[string]string {
		f := make(map[string]string, len(canon))
		for _, id := range canon {
			f[id] = err.reason
		}
		return f
	}
	switch {
	case err.auth:
		return nil, failAll()
	case err.tooLarge:
		if len(batch) > 1 {
			return c.split(batch)
		}
		return nil, failAll()
	default:
		if !retried {
			// Back off before the retry: under concurrency a failure is most
			// often a 429, and an immediate retry meets the same limit.
			time.Sleep(c.retryDelay)
			return c.runBatch(batch, true)
		}
		if len(batch) > 1 {
			return c.split(batch)
		}
		return nil, failAll()
	}
}

func (c *Client) split(batch []regoItem) (map[string]float64, map[string]string) {
	mid := len(batch) / 2
	a1, f1 := c.runBatch(batch[:mid], false)
	a2, f2 := c.runBatch(batch[mid:], false)
	ans := map[string]float64{}
	failed := map[string]string{}
	for k, v := range a1 {
		ans[k] = v
	}
	for k, v := range a2 {
		ans[k] = v
	}
	for k, v := range f1 {
		failed[k] = v
	}
	for k, v := range f2 {
		failed[k] = v
	}
	return ans, failed
}

// JudgeModules asks every Rego question about each module ON ITS OWN, in
// exactly the request shape lint sends a lone module, up to concurrency at
// once, and returns answers[i][question]. Calibration fits thresholds to these
// answers, so they must come from the same path lint uses; and a module left
// unanswered is an error, never a gap — a fit over partial data would be a
// threshold nobody measured.
func (c *Client) JudgeModules(regos []string, concurrency int) ([]map[string]float64, error) {
	items := make([]regoItem, len(regos))
	for i, r := range regos {
		items[i] = regoItem{field: "module_00", loc: fmt.Sprintf("module %d", i), rego: r}
	}
	answers, failed := c.judge(items, 1, concurrency, func(i int) string { return fmt.Sprintf("m%04d", i) })
	out := make([]map[string]float64, len(items))
	for i := range items {
		out[i] = map[string]float64{}
		for _, k := range regoKinds {
			id := qid(fmt.Sprintf("m%04d", i), k.name)
			p, ok := answers[id]
			if !ok {
				reason := failed[id]
				if reason == "" {
					reason = "no usable answer"
				}
				return nil, fmt.Errorf("module %d, %s: %s", i, k.name, reason)
			}
			out[i][k.name] = p
		}
	}
	return out, nil
}

// judge runs items through Jev, batchSize per request and up to concurrency
// requests at once. key(i) names item i in the returned maps; an item's field
// is what it travels under in a merged request, which need not be unique here
// because a lone module never uses it.
func (c *Client) judge(items []regoItem, batchSize, concurrency int, key func(int) string) (map[string]float64, map[string]string) {
	answers := map[string]float64{}
	failed := map[string]string{}
	if concurrency < 1 {
		concurrency = 1
	}
	type job struct {
		batch []regoItem
		keys  []string
	}
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		work = make(chan job)
	)
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				a, f := c.runBatch(j.batch, false)
				mu.Lock()
				for bi, it := range j.batch {
					for _, k := range regoKinds {
						from, to := qid(it.field, k.name), qid(j.keys[bi], k.name)
						if v, ok := a[from]; ok {
							answers[to] = v
						}
						if r, ok := f[from]; ok {
							failed[to] = r
						}
					}
				}
				mu.Unlock()
			}
		}()
	}
	next := 0
	for _, b := range chunkItems(items, batchSize, maxBatchBytes, len(regoKinds), maxQuestions) {
		keys := make([]string, len(b))
		for i := range b {
			keys[i] = key(next)
			next++
		}
		work <- job{b, keys}
	}
	close(work)
	wg.Wait()
	return answers, failed
}

// SemanticChecks are the judgments a schema validator cannot make. Modules are
// grouped batchSize per Jev request, and up to concurrency requests run at
// once. Findings are assembled afterwards in module order, so the result does
// not depend on which request finished first. repoContext is optional; when
// set it enables the over-scoped check.
//
// th decides, per question, what is a finding and what is a REVIEW: a
// probability in the review band is reported as unsure rather than dropped.
func SemanticChecks(p *Policy, c *Client, repoContext string, th Thresholds, batchSize, concurrency int) []Finding {
	items := regoItems(p)
	answers, failed := c.judge(items, batchSize, concurrency, func(i int) string { return items[i].field })
	var out []Finding
	for _, it := range items {
		ud := qid(it.field, "unconditional_deny")
		if pr, ok := answers[ud]; !ok {
			reason := failed[ud]
			if reason == "" {
				reason = "no usable answer"
			}
			out = append(out, Finding{Unknown, "could-not-check", it.loc,
				"Jev gave no answer (" + reason + ") — this module was not judged.", "", 0})
		} else if f, ok := judged(th.For("unconditional_deny"), pr, Finding{High, "unconditional-deny", it.loc,
			fmt.Sprintf("Rego appears to deny unconditionally (p=%.2f) — this rule refuses all evidence.", pr),
			"Guard the deny with a condition on the input, or remove the placeholder rule.", pr}); ok {
			out = append(out, f)
		}
		// One could-not-check per module is enough; an unanswered underspecified
		// question is not reported twice.
		if pr, ok := answers[qid(it.field, "underspecified")]; ok {
			if f, ok := judged(th.For("underspecified"), pr, Finding{Medium, "underspecified-check", it.loc,
				fmt.Sprintf("Rego may read a field without constraining it (p=%.2f) — it could admit what it looks like it checks.", pr),
				"Compare every field the decision depends on; a field read but not compared is a hole.", pr}); ok {
				out = append(out, f)
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
		} else if f, ok := judged(th.For("over_scoped"), pr, Finding{Medium, "over-scoped", loc,
			fmt.Sprintf("Policy may be over-scoped for this repo (p=%.2f): requires %s.", pr, strings.Join(types, ", ")),
			"Require only the attestation types this repository actually produces.", pr}); ok {
			out = append(out, f)
		}
	}
	return out
}

// judged applies a threshold to one answer: at or above Report the finding
// stands as written; in the review band it becomes a REVIEW saying Jev is
// unsure; below the band there is no finding.
func judged(t Threshold, pr float64, f Finding) (Finding, bool) {
	switch {
	case pr >= t.Report:
		return f, true
	case pr >= t.Review:
		f.Severity = Review
		f.Message = fmt.Sprintf("Jev is unsure (p=%.2f; reports at %.2f, reviews from %.2f) — read this module: %s",
			pr, t.Report, t.Review, f.Message)
		return f, true
	}
	return Finding{}, false
}
