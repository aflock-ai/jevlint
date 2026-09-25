package lint

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
)

const (
	// MinReportThreshold floors a fitted report threshold. A noul near 0.5 means
	// yes and no are about equally likely, so a corpus gap that happens to sit
	// lower does not license reporting below a coin flip.
	MinReportThreshold = 0.50
	// MinReviewFloor floors the review band — DeepEval's borderline band starts
	// at 0.35, and below it a module is a confident "no".
	MinReviewFloor = 0.35
)

// calibrationLock is the lock `jevlint calibrate` writes, compiled in so an
// installed binary carries the thresholds it was released with.
//
//go:embed calibration.lock.json
var calibrationLock []byte

// Threshold is where one question's probability becomes a finding. At or above
// Report is a finding; at or above Review but below Report is a REVIEW — Jev is
// unsure, a person should read the module. Review == Report means no band.
type Threshold struct {
	Report float64 `json:"report"`
	Review float64 `json:"review"`
}

// Thresholds resolves a Threshold per question, with a fallback for a question
// the lock does not cover (or cannot vouch for).
type Thresholds struct {
	ByKind   map[string]Threshold `json:"by_question,omitempty"`
	Fallback Threshold            `json:"fallback"`
	Source   string               `json:"source"`
}

// Uniform applies one report threshold to every question, with no review band —
// the behaviour before calibration, and what an explicit --min-prob asks for.
func Uniform(p float64) Thresholds {
	return Thresholds{Fallback: Threshold{p, p}, Source: fmt.Sprintf("--min-prob %.2f for every question", p)}
}

// For returns the threshold for one question.
func (t Thresholds) For(kind string) Threshold {
	if th, ok := t.ByKind[kind]; ok {
		return th
	}
	return t.Fallback
}

// QuestionCal is one question's fitted calibration.
type QuestionCal struct {
	Wording     string  `json:"wording_sha256"`
	Threshold   float64 `json:"threshold"`
	ReviewFloor float64 `json:"review_floor"`
	Precision   float64 `json:"precision"`
	Recall      float64 `json:"recall"`
	Separable   bool    `json:"separable"`
	MinPositive float64 `json:"min_positive"`
	MaxNegative float64 `json:"max_negative"`
	Noise       float64 `json:"noise"`
	Positives   int     `json:"positive_modules"`
	Negatives   int     `json:"negative_modules"`
}

// Calibration is the lock file: which model, which corpus, which wording, and
// the thresholds fitted from them. Any of the first three changing makes the
// thresholds unproven.
type Calibration struct {
	Model           string                 `json:"model"`
	Created         string                 `json:"created"`
	Corpus          string                 `json:"corpus_sha256"`
	Runs            int                    `json:"runs"`
	TargetPrecision float64                `json:"target_precision"`
	Questions       map[string]QuestionCal `json:"questions"`
}

// EmbeddedCalibration is the lock compiled into this binary.
func EmbeddedCalibration() (*Calibration, error) {
	var c Calibration
	if err := json.Unmarshal(calibrationLock, &c); err != nil {
		return nil, fmt.Errorf("embedded calibration lock: %w", err)
	}
	return &c, nil
}

// ReadCalibration loads a lock file from disk.
func ReadCalibration(path string) (*Calibration, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Calibration
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Thresholds turns the lock into per-question thresholds for a run on model.
// A question is used only when the lock covers it AND its wording hash matches
// the wording this binary sends: a threshold fitted to other words, or another
// model, is a guess, so that question falls back to fallback and a note says so.
func (c *Calibration) Thresholds(model string, fallback float64) (Thresholds, []string) {
	t := Thresholds{ByKind: map[string]Threshold{}, Fallback: Threshold{fallback, fallback}}
	var notes []string
	if model == "" {
		model = DefaultModel
	}
	if c.Model != model {
		t.Source = fmt.Sprintf("--min-prob %.2f (calibration is for %s, running %s)", fallback, c.Model, model)
		return t, append(notes, fmt.Sprintf("calibration lock is for %s but this run uses %s; every question uses --min-prob %.2f", c.Model, model, fallback))
	}
	for _, k := range regoKinds {
		q, ok := c.Questions[k.name]
		switch {
		case !ok:
			notes = append(notes, fmt.Sprintf("%s is not calibrated; using --min-prob %.2f", k.name, fallback))
		case q.Wording != WordingHash(k):
			notes = append(notes, fmt.Sprintf("%s wording changed since calibration; using --min-prob %.2f", k.name, fallback))
		default:
			t.ByKind[k.name] = Threshold{Report: q.Threshold, Review: q.ReviewFloor}
		}
	}
	t.Source = fmt.Sprintf("calibrated (%s, %s)", c.Model, c.Created)
	return t, notes
}

// WordingHash fingerprints everything a question sends — the lone wording, the
// batched wording, and both criteria — so any edit to them is detectable.
func WordingHash(k regoKind) string {
	h := sha256.New()
	for _, s := range []string{k.name, k.single, k.question("module_00"), k.trueMeans, k.falseMeans} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// QuestionWordingHash is WordingHash for a question named by name.
func QuestionWordingHash(name string) (string, bool) {
	for _, k := range regoKinds {
		if k.name == name {
			return WordingHash(k), true
		}
	}
	return "", false
}

// QuestionNames lists the calibratable questions in a fixed order.
func QuestionNames() []string {
	out := make([]string, len(regoKinds))
	for i, k := range regoKinds {
		out[i] = k.name
	}
	return out
}

// CorpusModule is one labeled Rego module.
type CorpusModule struct {
	ID     string          `json:"id"`
	File   string          `json:"file"`
	Labels map[string]bool `json:"labels"`
	Reason string          `json:"reason"`
	Rego   string          `json:"-"`
}

// Corpus is the labeled set thresholds are fitted to.
type Corpus struct {
	Modules []CorpusModule `json:"modules"`
	Hash    string         `json:"-"`
}

// LoadCorpus reads dir/corpus.json and every module it names. The hash covers
// the index and every module's bytes, so relabeling or editing a module changes
// it. Every module must carry a label for every question: a missing label would
// silently drop the module from one question's fit.
func LoadCorpus(dir string) (*Corpus, error) {
	idx, err := os.ReadFile(filepath.Join(dir, "corpus.json"))
	if err != nil {
		return nil, err
	}
	var c Corpus
	if err := json.Unmarshal(idx, &c); err != nil {
		return nil, fmt.Errorf("corpus.json: %w", err)
	}
	if len(c.Modules) == 0 {
		return nil, fmt.Errorf("corpus.json lists no modules")
	}
	h := sha256.New()
	h.Write(idx)
	seen := map[string]bool{}
	for i := range c.Modules {
		m := &c.Modules[i]
		if seen[m.ID] {
			return nil, fmt.Errorf("corpus: duplicate id %q", m.ID)
		}
		seen[m.ID] = true
		if filepath.Base(m.File) != m.File {
			return nil, fmt.Errorf("corpus: %s: file must be a bare name in the corpus dir, got %q", m.ID, m.File)
		}
		for _, q := range QuestionNames() {
			if _, ok := m.Labels[q]; !ok {
				return nil, fmt.Errorf("corpus: %s has no %q label", m.ID, q)
			}
		}
		b, err := os.ReadFile(filepath.Join(dir, m.File))
		if err != nil {
			return nil, fmt.Errorf("corpus: %s: %w", m.ID, err)
		}
		m.Rego = string(b)
		h.Write([]byte(m.File))
		h.Write([]byte{0})
		h.Write(b)
		h.Write([]byte{0})
	}
	c.Hash = hex.EncodeToString(h.Sum(nil))
	return &c, nil
}

// Observation is one labeled module's scores across repeated runs.
type Observation struct {
	Positive bool
	Scores   []float64
}

// Fit picks one question's thresholds from labeled observations.
//
// If every positive score sits above every negative score, the report threshold
// is the middle of the gap (the widest margin either side). Otherwise it is the
// lowest observed score that still meets targetPrecision. The review band
// starts at the lower of "highest negative + noise" and "lowest positive −
// noise", where noise is the widest run-to-run spread of any one module. Both are floored
// (MinReportThreshold, MinReviewFloor), and precision and recall are reported
// at the threshold actually chosen, so the lock never claims more than it has.
func Fit(obs []Observation, targetPrecision float64) (QuestionCal, error) {
	var pos, neg []float64
	var q QuestionCal
	for _, o := range obs {
		if len(o.Scores) == 0 {
			return q, fmt.Errorf("an observation has no scores")
		}
		lo, hi := o.Scores[0], o.Scores[0]
		for _, s := range o.Scores {
			lo, hi = math.Min(lo, s), math.Max(hi, s)
		}
		q.Noise = math.Max(q.Noise, hi-lo)
		if o.Positive {
			q.Positives++
			pos = append(pos, o.Scores...)
		} else {
			q.Negatives++
			neg = append(neg, o.Scores...)
		}
	}
	if len(pos) == 0 || len(neg) == 0 {
		return q, fmt.Errorf("need both positive and negative modules (have %d / %d)", q.Positives, q.Negatives)
	}
	sort.Float64s(pos)
	sort.Float64s(neg)
	q.MinPositive, q.MaxNegative = pos[0], neg[len(neg)-1]
	q.Separable = q.MinPositive > q.MaxNegative

	// The review band starts just above the negatives (plus noise) — but never
	// above the weakest positive (minus noise), so a positive that lands under
	// the report threshold, because the floor below lifted it or because Jev's
	// run-to-run spread is wide, is sent to review rather than dropped. A
	// spurious REVIEW costs a reader a minute; a dropped positive is the miss.
	review := math.Min(q.MaxNegative+q.Noise, q.MinPositive-q.Noise)
	var threshold float64
	if q.Separable {
		threshold = (q.MinPositive + q.MaxNegative) / 2
	} else {
		cands := append(append([]float64{}, pos...), neg...)
		sort.Float64s(cands)
		found := false
		for _, t := range cands {
			if p, r := precisionRecall(pos, neg, t); r > 0 && p >= targetPrecision {
				threshold, found = t, true
				break
			}
		}
		if !found {
			return q, fmt.Errorf("no threshold reaches precision %.2f: a negative outscores every positive", targetPrecision)
		}
	}
	// Round to two places — up for the threshold, down for the band — with a
	// tolerance so 0.52 stored as 0.52000000000000002 stays 0.52.
	threshold = math.Ceil(math.Max(threshold, MinReportThreshold)*100-1e-6) / 100
	review = math.Floor(math.Max(review, MinReviewFloor)*100+1e-6) / 100
	q.Threshold = threshold
	q.ReviewFloor = math.Min(review, threshold)
	q.Precision, q.Recall = precisionRecall(pos, neg, threshold)
	q.Noise = math.Round(q.Noise*1000) / 1000
	return q, nil
}

// precisionRecall scores the rule "report at or above t" over every observed
// score. With nothing reported, precision is vacuously 1.
func precisionRecall(pos, neg []float64, t float64) (precision, recall float64) {
	tp, fp := 0, 0
	for _, s := range pos {
		if s >= t {
			tp++
		}
	}
	for _, s := range neg {
		if s >= t {
			fp++
		}
	}
	precision = 1
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	return precision, float64(tp) / float64(len(pos))
}

// Evaluate scores observations against a FIXED threshold — the drift check
// re-runs the corpus and asks whether the locked thresholds still hold.
func Evaluate(obs []Observation, threshold float64) (precision, recall float64) {
	var pos, neg []float64
	for _, o := range obs {
		if o.Positive {
			pos = append(pos, o.Scores...)
		} else {
			neg = append(neg, o.Scores...)
		}
	}
	if len(pos) == 0 {
		return 1, 0
	}
	return precisionRecall(pos, neg, threshold)
}
