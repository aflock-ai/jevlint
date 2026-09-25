package lint

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeJev answers every noul as a pure function of the module the question is
// about: "ALWAYS_DENY" in the module → unconditional_deny 0.97, "UNDERSPEC" →
// underspecified 0.91, otherwise low. Because the answer depends only on the
// module's own content, any mix-up in how answers are mapped back to modules
// shows up as a wrong finding. It also asserts every question names its field.
type fakeJev struct {
	t        *testing.T
	calls    atomic.Int32
	status   func(call int32, state map[string]string) int // optional override
	maxState int                                           // 0 = unlimited
}

func (f *fakeJev) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call := f.calls.Add(1)
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		State     map[string]string `json:"state"`
		Questions map[string]struct {
			Instructions struct {
				Question string `json:"question"`
			} `json:"instructions"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		f.t.Errorf("request is not JSON: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if f.status != nil {
		if s := f.status(call, req.State); s != http.StatusOK {
			w.WriteHeader(s)
			if s == http.StatusBadRequest {
				_, _ = w.Write([]byte(`{"detail":{"error_type":"max_tokens_exceeded"}}`))
			}
			return
		}
	}
	answers := map[string]any{}
	for id, q := range req.Questions {
		field, kind, named := strings.Cut(id, "__")
		if !named {
			// A lone module travels in the pre-batching shape: state {"rego": …}
			// and a plain question id.
			field, kind = "rego", id
			if len(req.State) != 1 {
				f.t.Errorf("plain question id %q in a %d-module request", id, len(req.State))
			}
		}
		rego, present := req.State[field]
		if !present {
			f.t.Errorf("question %q names field %q absent from state", id, field)
			continue
		}
		if named && !strings.Contains(q.Instructions.Question, "`"+field+"`") {
			f.t.Errorf("question %q does not reference its own field", id)
		}
		p := 0.04
		switch {
		case kind == "unconditional_deny" && strings.Contains(rego, "ALWAYS_DENY"):
			p = 0.97
		case kind == "underspecified" && strings.Contains(rego, "UNDERSPEC"):
			p = 0.91
		}
		answers[id] = map[string]any{"type": "noul", "noul": p}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"answers": answers})
}

func policyWith(modules []string) *Policy {
	var rps []RegoPolicy
	for i, m := range modules {
		rps = append(rps, RegoPolicy{Name: fmt.Sprintf("r%02d", i), Module: base64.StdEncoding.EncodeToString([]byte(m))})
	}
	return &Policy{Steps: map[string]Step{"s": {Attestations: []Attestation{{Type: "t", RegoPolicies: rps}}}}}
}

func testClient(url string) *Client {
	c := NewClient("", "test-key")
	c.endpoint = url
	c.retryDelay = 0
	return c
}

func findingSet(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Check+" @ "+f.Location)
	}
	sort.Strings(out)
	return out
}

// Eleven modules like the real pushgate policy: one unconditional deny and one
// underspecified module among nine clean ones.
func mixedModules() []string {
	m := make([]string, 11)
	for i := range m {
		m[i] = fmt.Sprintf("package p%d\ndeny[msg] { input.x == %d; msg := \"clean\" }", i, i)
	}
	m[3] = "package p3\ndeny[msg] { msg := \"ALWAYS_DENY\" }"
	m[8] = "package p8\ndeny[msg] { UNDERSPEC input.y; msg := \"x\" }"
	return m
}

func TestChunkItems(t *testing.T) {
	mk := func(n int, size int) []regoItem {
		items := make([]regoItem, n)
		for i := range items {
			items[i] = regoItem{field: fmt.Sprintf("module_%02d", i), rego: strings.Repeat("x", size)}
		}
		return items
	}
	if got := chunkItems(mk(11, 10), 8, 1<<20, 2, 128); len(got) != 2 || len(got[0]) != 8 || len(got[1]) != 3 {
		t.Errorf("11 items at size 8: want [8 3], got %d batches", len(got))
	}
	if got := chunkItems(mk(11, 10), 1, 1<<20, 2, 128); len(got) != 11 {
		t.Errorf("size 1: want 11 batches, got %d", len(got))
	}
	// byte budget: 4 items of 100 bytes under a 250-byte budget → 2 per batch.
	if got := chunkItems(mk(4, 100), 8, 250, 2, 128); len(got) != 2 {
		t.Errorf("byte budget: want 2 batches, got %d", len(got))
	}
	// an item larger than the budget travels alone.
	items := append(mk(2, 10), regoItem{field: "module_99", rego: strings.Repeat("y", 500)})
	got := chunkItems(items, 8, 100, 2, 128)
	if len(got) != 2 || len(got[1]) != 1 || got[1][0].field != "module_99" {
		t.Errorf("oversize item must travel alone, got %d batches", len(got))
	}
	// question ceiling: 2 questions per item, ceiling 6 → 3 items per batch.
	if got := chunkItems(mk(7, 10), 8, 1<<20, 2, 6); len(got) != 3 {
		t.Errorf("question ceiling: want 3 batches, got %d", len(got))
	}
}

// The mapping test: every batch size AND every concurrency level must produce
// exactly the same findings when Jev's answers depend only on each module's
// content. Concurrency reorders completion; the result must not depend on it.
func TestBatch_SameFindingsAtEveryBatchSizeAndConcurrency(t *testing.T) {
	p := policyWith(mixedModules())
	var want []string
	for _, size := range []int{1, 2, 3, 8, 11, 64} {
		for _, conc := range []int{1, 4, 16} {
			f := &fakeJev{t: t}
			srv := httptest.NewServer(f)
			c := testClient(srv.URL)
			got := findingSet(SemanticChecks(p, c, "", Uniform(0.70), size, conc))
			srv.Close()
			if want == nil {
				want = got
				if len(want) != 2 {
					t.Fatalf("baseline should flag module 3 (deny) and module 8 (underspec), got %v", want)
				}
			}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Errorf("batch %d, concurrency %d changed findings:\n got  %v\n want %v", size, conc, got, want)
			}
			if wantReq := (11 + size - 1) / size; c.Requests() != wantReq {
				t.Errorf("batch %d: want %d requests, got %d", size, wantReq, c.Requests())
			}
			if c.Questions() != 22 {
				t.Errorf("batch %d: want 22 questions, got %d", size, c.Questions())
			}
		}
	}
}

func TestBatch_MissingAnswerIsCouldNotCheckForThatModuleOnly(t *testing.T) {
	// A server that silently drops module_05's answers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Questions map[string]any `json:"questions"`
		}
		_ = json.Unmarshal(raw, &req)
		ans := map[string]any{}
		for id := range req.Questions {
			if strings.HasPrefix(id, "module_05__") {
				continue
			}
			ans[id] = map[string]any{"noul": 0.02}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"answers": ans})
	}))
	defer srv.Close()
	fs := SemanticChecks(policyWith(mixedModules()), testClient(srv.URL), "", Uniform(0.70), 8, 4)
	cnc := 0
	for _, f := range fs {
		if f.Check == "could-not-check" {
			cnc++
			if !strings.Contains(f.Location, "r05") {
				t.Errorf("could-not-check on the wrong module: %s", f.Location)
			}
		}
	}
	if cnc != 1 {
		t.Errorf("want exactly 1 could-not-check (module 5), got %d: %v", cnc, findingSet(fs))
	}
}

func TestBatch_TooLargeSplitsAndIsolatesTheBigModule(t *testing.T) {
	mods := mixedModules()
	mods[6] = "package huge\n# HUGE\ndeny[msg] { input.z; msg := \"x\" }"
	f := &fakeJev{t: t, status: func(_ int32, st map[string]string) int {
		for _, rego := range st {
			if strings.Contains(rego, "HUGE") {
				return http.StatusBadRequest // max_tokens_exceeded
			}
		}
		return http.StatusOK
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	fs := SemanticChecks(policyWith(mods), testClient(srv.URL), "", Uniform(0.70), 11, 4)
	got := findingSet(fs)
	wantCNC := "could-not-check @ step s · t · r06"
	var sawCNC, sawDeny, sawUnder bool
	for _, g := range got {
		switch {
		case g == wantCNC:
			sawCNC = true
		case strings.HasPrefix(g, "could-not-check"):
			t.Errorf("a module other than the oversize one went unjudged: %s", g)
		case g == "unconditional-deny @ step s · t · r03":
			sawDeny = true
		case g == "underspecified-check @ step s · t · r08":
			sawUnder = true
		}
	}
	if !sawCNC || !sawDeny || !sawUnder {
		t.Errorf("splitting must isolate r06 and still judge r03/r08, got %v", got)
	}
}

func TestBatch_AuthFailureIsFinalNoRetryNoSplit(t *testing.T) {
	f := &fakeJev{t: t, status: func(int32, map[string]string) int { return http.StatusUnauthorized }}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := testClient(srv.URL)
	fs := SemanticChecks(policyWith(mixedModules()), c, "", Uniform(0.70), 8, 4)
	if c.Requests() != 2 {
		t.Errorf("auth failure: want 2 requests (one per chunk, no retry or split), got %d", c.Requests())
	}
	if n := CountCNC(fs); n != 11 {
		t.Errorf("auth failure: every module must be could-not-check, got %d", n)
	}
}

func TestBatch_TransientFailureIsRetriedOnce(t *testing.T) {
	f := &fakeJev{t: t, status: func(call int32, _ map[string]string) int {
		if call == 1 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := testClient(srv.URL)
	fs := SemanticChecks(policyWith(mixedModules()), c, "", Uniform(0.70), 11, 4)
	if c.Requests() != 2 {
		t.Errorf("want 1 failed + 1 retried request, got %d", c.Requests())
	}
	if CountCNC(fs) != 0 || len(fs) != 2 {
		t.Errorf("after a successful retry, want the 2 real findings and no could-not-check, got %v", findingSet(fs))
	}
}

// A lone module must be sent EXACTLY as the pre-batching client sent it: every
// single-module policy is a batch of one, and measurement showed the opaque
// named-field form losing signal there.
func TestBatch_LoneModuleUsesThePreBatchingRequestShape(t *testing.T) {
	var seen struct {
		State     map[string]string `json:"state"`
		Questions map[string]struct {
			Instructions struct {
				Question string `json:"question"`
			} `json:"instructions"`
		} `json:"questions"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &seen)
		_ = json.NewEncoder(w).Encode(map[string]any{"answers": map[string]any{
			"unconditional_deny": map[string]any{"noul": 0.95},
			"underspecified":     map[string]any{"noul": 0.02},
		}})
	}))
	defer srv.Close()
	fs := SemanticChecks(policyWith([]string{"package p\ndeny[msg] { msg := \"x\" }"}), testClient(srv.URL), "", Uniform(0.70), 8, 4)

	if len(seen.State) != 1 || seen.State["rego"] == "" {
		t.Errorf("lone module: state must be exactly {\"rego\": …}, got keys %v", keys(seen.State))
	}
	for _, k := range regoKinds {
		q, ok := seen.Questions[k.name]
		if !ok {
			t.Errorf("lone module: question id must be the plain %q", k.name)
			continue
		}
		if q.Instructions.Question != k.single {
			t.Errorf("lone module: %q must use the pre-batching wording", k.name)
		}
	}
	if len(fs) != 1 || fs[0].Check != "unconditional-deny" {
		t.Errorf("the lone module's answer must map back to it, got %v", findingSet(fs))
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestRegoItems_DeterministicOrder(t *testing.T) {
	p := &Policy{Steps: map[string]Step{}}
	for _, s := range []string{"zeta", "alpha", "mid", "beta"} {
		p.Steps[s] = Step{Attestations: []Attestation{{Type: "t", RegoPolicies: []RegoPolicy{{Name: "r", Module: base64.StdEncoding.EncodeToString([]byte("package x"))}}}}}
	}
	first := regoItems(p)
	for i := 0; i < 20; i++ {
		again := regoItems(p)
		for j := range first {
			if first[j].loc != again[j].loc || first[j].field != again[j].field {
				t.Fatalf("module order changed between runs: %v vs %v", first[j].loc, again[j].loc)
			}
		}
	}
}
