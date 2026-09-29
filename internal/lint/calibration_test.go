package lint

import (
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func obs(positive bool, scores ...float64) Observation {
	return Observation{Positive: positive, Scores: scores}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestFit_SeparableTakesTheMidpointAndReviewsAboveTheNoise(t *testing.T) {
	q, err := Fit([]Observation{
		obs(true, 0.73, 0.75), obs(true, 0.95, 0.97),
		obs(false, 0.31, 0.29), obs(false, 0.10, 0.12),
	}, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if !q.Separable || !near(q.MinPositive, 0.73) || !near(q.MaxNegative, 0.31) {
		t.Fatalf("fit = %+v", q)
	}
	// midpoint (0.31+0.73)/2 = 0.52; review = 0.31 + noise 0.02 = 0.33 → floored to 0.35
	if !near(q.Threshold, 0.52) || !near(q.ReviewFloor, 0.35) {
		t.Fatalf("threshold %.3f review %.3f, want 0.52 / 0.35", q.Threshold, q.ReviewFloor)
	}
	if q.Precision != 1 || q.Recall != 1 {
		t.Fatalf("precision %.2f recall %.2f, want 1 / 1", q.Precision, q.Recall)
	}
}

func TestFit_ReviewBandStartsAboveTheHighestNegativePlusNoise(t *testing.T) {
	q, err := Fit([]Observation{obs(true, 0.90, 0.92), obs(false, 0.40, 0.45)}, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	// noise = 0.05; review = 0.45 + 0.05 = 0.50; threshold = (0.45+0.90)/2 = 0.675 → 0.68
	if !near(q.ReviewFloor, 0.50) || !near(q.Threshold, 0.68) {
		t.Fatalf("review %.3f threshold %.3f, want 0.50 / 0.68", q.ReviewFloor, q.Threshold)
	}
}

// Measured on the real corpus: one underspecified module scored 0.46–0.69
// across three identical requests. The coin-flip floor lifts the threshold to
// 0.50, above that positive's low run — the band must catch it, not drop it.
func TestFit_NoisyPositiveBelowTheFloorLandsInReview(t *testing.T) {
	q, err := Fit([]Observation{obs(true, 0.46, 0.69), obs(true, 0.90, 0.93), obs(false, 0.31, 0.29)}, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if !near(q.Threshold, 0.50) || !near(q.ReviewFloor, 0.35) {
		t.Fatalf("threshold %.3f review %.3f, want 0.50 / 0.35", q.Threshold, q.ReviewFloor)
	}
	if f, ok := judged(Threshold{q.Threshold, q.ReviewFloor}, 0.46, Finding{Severity: Medium}); !ok || f.Severity != Review {
		t.Fatalf("a 0.46 positive must be a REVIEW, got %+v %v", f, ok)
	}
}

func TestFit_OverlapPicksTheLowestThresholdThatMeetsPrecision(t *testing.T) {
	q, err := Fit([]Observation{
		obs(true, 0.60, 0.62), obs(true, 0.90, 0.91),
		obs(false, 0.70, 0.71), obs(false, 0.20, 0.20),
	}, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if q.Separable {
		t.Fatal("overlapping classes reported separable")
	}
	// Only at or above 0.90 is nothing negative reported.
	if !near(q.Threshold, 0.90) || q.Precision != 1 || !near(q.Recall, 0.5) {
		t.Fatalf("fit = %+v", q)
	}
	// The band reaches down toward the weakest positive (0.60 − noise 0.02).
	if !near(q.ReviewFloor, 0.58) {
		t.Fatalf("review %.3f, want 0.58", q.ReviewFloor)
	}
}

func TestFit_NeverReportsBelowACoinFlip(t *testing.T) {
	q, err := Fit([]Observation{obs(true, 0.40, 0.41), obs(false, 0.05, 0.06)}, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if q.Threshold < MinReportThreshold {
		t.Fatalf("threshold %.2f is below the %.2f floor", q.Threshold, MinReportThreshold)
	}
	// The floor costs recall here, and the lock must say so rather than claim 1.
	if q.Recall != 0 {
		t.Fatalf("recall %.2f: positives at 0.40 cannot be reported at %.2f", q.Recall, q.Threshold)
	}
}

func TestFit_RefusesWhatItCannotMeasure(t *testing.T) {
	if _, err := Fit([]Observation{obs(true, 0.9, 0.9)}, 1.0); err == nil {
		t.Error("fit with no negatives should fail")
	}
	if _, err := Fit([]Observation{obs(false, 0.1, 0.1)}, 1.0); err == nil {
		t.Error("fit with no positives should fail")
	}
	// A negative above every positive: no threshold is precise.
	if _, err := Fit([]Observation{obs(true, 0.6, 0.6), obs(false, 0.99, 0.99)}, 1.0); err == nil {
		t.Error("fit where a negative outscores every positive should fail")
	}
}

func TestJudged_ThreeBands(t *testing.T) {
	th := Threshold{Report: 0.60, Review: 0.40}
	base := Finding{Severity: Medium, Check: "underspecified-check", Message: "m"}
	if f, ok := judged(th, 0.61, base); !ok || f.Severity != Medium {
		t.Errorf("0.61: got %+v %v, want a MEDIUM finding", f, ok)
	}
	if f, ok := judged(th, 0.60, base); !ok || f.Severity != Medium {
		t.Errorf("0.60 is at the threshold and must report: got %+v %v", f, ok)
	}
	if f, ok := judged(th, 0.45, base); !ok || f.Severity != Review || !strings.Contains(f.Message, "unsure") {
		t.Errorf("0.45: got %+v %v, want a REVIEW", f, ok)
	}
	if _, ok := judged(th, 0.39, base); ok {
		t.Error("0.39 is below the review band and must not be reported")
	}
	// Uniform thresholds have no band: below Report is nothing.
	if _, ok := judged(Uniform(0.70).For("underspecified"), 0.69, base); ok {
		t.Error("uniform threshold reported below itself")
	}
}

func calFor(model string) *Calibration {
	c := &Calibration{Model: model, Questions: map[string]QuestionCal{}}
	for _, k := range regoKinds {
		c.Questions[k.name] = QuestionCal{Wording: WordingHash(k), Threshold: 0.55, ReviewFloor: 0.40}
	}
	return c
}

func TestThresholds_UsesTheLockOnlyWhereItCanVouch(t *testing.T) {
	c := calFor(DefaultModel)
	th, notes := c.Thresholds("", 0.70)
	if len(notes) != 0 || th.For("unconditional_deny").Report != 0.55 || th.For("underspecified").Review != 0.40 {
		t.Fatalf("matching lock not applied: %+v %v", th, notes)
	}
	if got := th.For("over_scoped"); got.Report != 0.70 || got.Review != 0.70 {
		t.Errorf("uncalibrated question should fall back to 0.70 with no band, got %+v", got)
	}

	// A question whose wording moved falls back, and says so.
	q := c.Questions["underspecified"]
	q.Wording = "stale"
	c.Questions["underspecified"] = q
	th, notes = c.Thresholds("", 0.70)
	if th.For("underspecified").Report != 0.70 || th.For("unconditional_deny").Report != 0.55 {
		t.Errorf("stale wording not isolated to its question: %+v", th)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "wording changed") {
		t.Errorf("notes = %v", notes)
	}
}

func TestThresholds_AnotherModelUsesNoCalibration(t *testing.T) {
	th, notes := calFor(DefaultModel).Thresholds("jev-9.9.9", 0.70)
	if len(th.ByKind) != 0 || th.For("unconditional_deny").Report != 0.70 || len(notes) != 1 {
		t.Fatalf("thresholds fitted on %s applied to another model: %+v %v", DefaultModel, th, notes)
	}
}

// The shipped lock must vouch for exactly what this binary sends: the pinned
// model, the current wording of every question, and the corpus as committed.
// This is the offline half of the drift gate — it needs no key, so it runs on
// every PR. A wording edit, a relabel, or a model bump without re-running
// `jevlint calibrate` fails here.
func TestCalibrationLock_VouchesForThisBinaryAndCorpus(t *testing.T) {
	c, err := EmbeddedCalibration()
	if err != nil {
		t.Fatal(err)
	}
	if c.Model != DefaultModel {
		t.Errorf("lock model %q, binary pins %q — re-run jevlint calibrate", c.Model, DefaultModel)
	}
	for _, k := range regoKinds {
		q, ok := c.Questions[k.name]
		if !ok {
			t.Errorf("%s is not in the lock — re-run jevlint calibrate", k.name)
			continue
		}
		if q.Wording != WordingHash(k) {
			t.Errorf("%s wording changed since calibration — re-run jevlint calibrate", k.name)
		}
		if q.ReviewFloor > q.Threshold || q.Threshold < MinReportThreshold {
			t.Errorf("%s: review %.2f / threshold %.2f is not a valid band", k.name, q.ReviewFloor, q.Threshold)
		}
	}
	corpus, err := LoadCorpus(filepath.Join("..", "..", "testdata", "calibration"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Corpus != corpus.Hash {
		t.Error("corpus changed since calibration — re-run jevlint calibrate")
	}
}

func TestLoadCorpus_RefusesAnIncompleteOrEscapingIndex(t *testing.T) {
	write := func(index string) string {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "corpus.json"), []byte(index), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "a.rego"), []byte("package a\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	for name, index := range map[string]string{
		"missing label": `{"modules":[{"id":"a","file":"a.rego","labels":{"unconditional_deny":true}}]}`,
		"escaping path": `{"modules":[{"id":"a","file":"../a.rego","labels":{"unconditional_deny":true,"underspecified":false}}]}`,
		"duplicate id":  `{"modules":[{"id":"a","file":"a.rego","labels":{"unconditional_deny":true,"underspecified":false}},{"id":"a","file":"a.rego","labels":{"unconditional_deny":true,"underspecified":false}}]}`,
		"empty":         `{"modules":[]}`,
	} {
		if _, err := LoadCorpus(write(index)); err == nil {
			t.Errorf("%s: loaded without error", name)
		}
	}
	// And the hash moves when a label does.
	a, err := LoadCorpus(write(`{"modules":[{"id":"a","file":"a.rego","labels":{"unconditional_deny":true,"underspecified":false}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadCorpus(write(`{"modules":[{"id":"a","file":"a.rego","labels":{"unconditional_deny":false,"underspecified":false}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash == b.Hash {
		t.Error("relabeling a module did not change the corpus hash")
	}
}

func TestSemanticChecks_ReviewBandIsShownNotFailed(t *testing.T) {
	srv := httptest.NewServer(&fakeJev{t: t})
	defer srv.Close()
	// fakeJev answers underspecified 0.91 for UNDERSPEC modules; put the band
	// around it so it lands as a REVIEW, and the unconditional deny (0.97) above.
	th := Thresholds{ByKind: map[string]Threshold{
		"unconditional_deny": {Report: 0.60, Review: 0.40},
		"underspecified":     {Report: 0.95, Review: 0.80},
	}, Fallback: Threshold{0.70, 0.70}}
	fs := SemanticChecks(policyWith(mixedModules()), testClient(srv.URL), "", th, 1, 4)
	var high, review int
	for _, f := range fs {
		switch {
		case f.Check == "unconditional-deny" && f.Severity == High:
			high++
		case f.Check == "underspecified-check" && f.Severity == Review:
			review++
		default:
			t.Errorf("unexpected finding %+v", f)
		}
	}
	if high != 1 || review != 1 || CountReview(fs) != 1 {
		t.Fatalf("high=%d review=%d, want 1 and 1: %+v", high, review, fs)
	}
}

func TestJudgeModules_UsesTheLoneShapeAndRefusesPartialAnswers(t *testing.T) {
	srv := httptest.NewServer(&fakeJev{t: t})
	defer srv.Close()
	got, err := testClient(srv.URL).JudgeModules([]string{
		"package a\ndeny[msg] { msg := \"ALWAYS_DENY\" }",
		"package b\ndeny[msg] { input.x == 1; msg := \"clean\" }",
		"package a\ndeny[msg] { msg := \"ALWAYS_DENY\" }", // a repeat run
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0]["unconditional_deny"] != 0.97 || got[1]["unconditional_deny"] != 0.04 || got[2]["unconditional_deny"] != 0.97 {
		t.Fatalf("answers mapped to the wrong modules: %+v", got)
	}

	fail := httptest.NewServer(&fakeJev{t: t, status: func(int32, map[string]string) int { return 502 }})
	defer fail.Close()
	if _, err := testClient(fail.URL).JudgeModules([]string{"package a\n"}, 1); err == nil {
		t.Fatal("a module Jev never answered must fail calibration, not be skipped")
	}
}
