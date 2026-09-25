package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/jevlint/internal/lint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var calibrateCmd = &cobra.Command{
	Use:   "calibrate",
	Short: "Fit per-question thresholds to a labeled corpus, or check the locked ones still hold",
	Long: `calibrate runs every module of a labeled corpus through Jev --runs times, in
exactly the request shape lint uses, and fits each question a report threshold
and a review band. The result is written to a lock file, which lint uses.

With --check it fits nothing. It refuses if the model, the corpus or a
question's wording no longer match the lock, then re-runs the corpus and fails
if precision or recall at the locked thresholds dropped by more than
--tolerance. Use it in CI so a wording edit or a model move cannot silently
change what jevlint reports.

Exit codes: 0 ok · 1 drift or a stale lock · 2 Jev could not answer or error.`,
	Args: cobra.NoArgs,
	RunE: runCalibrate,
}

func init() {
	f := calibrateCmd.Flags()
	f.String("corpus", "testdata/calibration", "labeled corpus directory (holds corpus.json)")
	f.String("lock", "internal/lint/calibration.lock.json", "lock file to write, or with --check to verify")
	f.Int("runs", 3, "times each module is judged; the spread between runs is the noise the review band absorbs")
	f.Float64("target-precision", 1.0, "precision a threshold must reach on the corpus when positives and negatives overlap")
	f.Bool("check", false, "verify the lock instead of writing it")
	f.Float64("tolerance", 0.05, "with --check: how far precision or recall may fall below the lock")
	f.Int("concurrency", lint.DefaultConcurrency, "Jev requests in flight at once")
}

func runCalibrate(cmd *cobra.Command, _ []string) error {
	dir, _ := cmd.Flags().GetString("corpus")
	lockPath, _ := cmd.Flags().GetString("lock")
	runs, _ := cmd.Flags().GetInt("runs")
	target, _ := cmd.Flags().GetFloat64("target-precision")
	check, _ := cmd.Flags().GetBool("check")
	tol, _ := cmd.Flags().GetFloat64("tolerance")
	conc, _ := cmd.Flags().GetInt("concurrency")
	model := effectiveModel(viper.GetString("model"))
	if runs < 2 {
		return fmt.Errorf("--runs must be at least 2: one run cannot measure noise")
	}
	if target <= 0 || target > 1 {
		return fmt.Errorf("--target-precision must be in (0, 1], got %v", target)
	}

	corpus, err := lint.LoadCorpus(dir)
	if err != nil {
		return err
	}

	var lock *lint.Calibration
	if check {
		if lock, err = lint.ReadCalibration(lockPath); err != nil {
			return err
		}
		// Stale-lock problems are decided before any request is spent.
		if stale := staleLock(lock, corpus, model); len(stale) > 0 {
			for _, s := range stale {
				fmt.Println("  STALE  " + s)
			}
			fmt.Println("calibration lock is stale — re-run `jevlint calibrate` and commit the new lock")
			os.Exit(1)
		}
	}

	c := lint.NewClient(model, viper.GetString("api-key"))
	if !c.HasKey() {
		return fmt.Errorf("no API key (TYPESAFE_API_KEY / JEVLINT_API_KEY / ~/.config/typesafe/api_key / keychain)")
	}
	regos := make([]string, 0, len(corpus.Modules)*runs)
	for r := 0; r < runs; r++ {
		for _, m := range corpus.Modules {
			regos = append(regos, m.Rego)
		}
	}
	answers, err := c.JudgeModules(regos, conc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jevlint calibrate: could not judge the corpus: "+err.Error())
		os.Exit(2)
	}
	obs := map[string][]lint.Observation{}
	for _, q := range lint.QuestionNames() {
		for mi, m := range corpus.Modules {
			o := lint.Observation{Positive: m.Labels[q]}
			for r := 0; r < runs; r++ {
				o.Scores = append(o.Scores, answers[r*len(corpus.Modules)+mi][q])
			}
			obs[q] = append(obs[q], o)
		}
	}
	fmt.Printf("jevlint calibrate  %s (%d modules × %d runs, %s)\n", dir, len(corpus.Modules), runs, model)
	fmt.Printf("  jev: %d request(s) for %d question(s)\n", c.Requests(), c.Questions())

	if check {
		drift := false
		for _, q := range lint.QuestionNames() {
			want := lock.Questions[q]
			p, r := lint.Evaluate(obs[q], want.Threshold)
			status := "ok"
			if p < want.Precision-tol || r < want.Recall-tol {
				status, drift = "DRIFT", true
			}
			fmt.Printf("  %-5s  %-20s threshold %.2f  precision %.2f (lock %.2f)  recall %.2f (lock %.2f)\n",
				status, q, want.Threshold, p, want.Precision, r, want.Recall)
			printMisses(corpus, obs[q], want.Threshold, want.ReviewFloor)
		}
		if drift {
			fmt.Println("calibration drifted beyond ±" + fmt.Sprint(tol) + " — re-run `jevlint calibrate`, review the new thresholds, and commit the lock")
			os.Exit(1)
		}
		return nil
	}

	cal := lint.Calibration{
		Model:           model,
		Created:         time.Now().UTC().Format("2006-01-02"),
		Corpus:          corpus.Hash,
		Runs:            runs,
		TargetPrecision: target,
		Questions:       map[string]lint.QuestionCal{},
	}
	for _, q := range lint.QuestionNames() {
		fit, err := lint.Fit(obs[q], target)
		if err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
		fit.Wording, _ = lint.QuestionWordingHash(q)
		cal.Questions[q] = fit
		sep := "separable"
		if !fit.Separable {
			sep = "OVERLAP"
		}
		fmt.Printf("  %-20s report ≥ %.2f  review ≥ %.2f  precision %.2f  recall %.2f  (%s: positives ≥ %.2f, negatives ≤ %.2f, noise %.2f; %d+/%d−)\n",
			q, fit.Threshold, fit.ReviewFloor, fit.Precision, fit.Recall, sep, fit.MinPositive, fit.MaxNegative, fit.Noise, fit.Positives, fit.Negatives)
		printMisses(corpus, obs[q], fit.Threshold, fit.ReviewFloor)
	}
	out, _ := json.MarshalIndent(cal, "", "  ")
	if err := os.WriteFile(lockPath, append(out, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Println("  wrote " + lockPath + " — rebuild so lint picks it up")
	return nil
}

// staleLock lists why a lock can no longer vouch for this binary and corpus.
func staleLock(lock *lint.Calibration, corpus *lint.Corpus, model string) []string {
	var out []string
	if lock.Model != model {
		out = append(out, fmt.Sprintf("model: lock %q, running %q", lock.Model, model))
	}
	if lock.Corpus != corpus.Hash {
		out = append(out, "corpus: its modules or labels changed since the lock was written")
	}
	for _, q := range lint.QuestionNames() {
		lq, ok := lock.Questions[q]
		if !ok {
			out = append(out, q+": not in the lock")
			continue
		}
		if h, _ := lint.QuestionWordingHash(q); lq.Wording != h {
			out = append(out, q+": its wording changed since the lock was written")
		}
	}
	return out
}

// printMisses names every module a threshold gets wrong on some run, and every
// module that lands in the review band, so a fit can be read, not just trusted.
func printMisses(corpus *lint.Corpus, obs []lint.Observation, report, review float64) {
	var lines []string
	for i, o := range obs {
		lo, hi := o.Scores[0], o.Scores[0]
		for _, s := range o.Scores {
			if s < lo {
				lo = s
			}
			if s > hi {
				hi = s
			}
		}
		id := corpus.Modules[i].ID
		switch {
		case o.Positive && lo < review:
			lines = append(lines, fmt.Sprintf("MISSED    %-26s positive scored %.2f–%.2f", id, lo, hi))
		case o.Positive && lo < report:
			lines = append(lines, fmt.Sprintf("REVIEW    %-26s positive scored %.2f–%.2f", id, lo, hi))
		case !o.Positive && hi >= report:
			lines = append(lines, fmt.Sprintf("FALSE-POS %-26s negative scored %.2f–%.2f", id, lo, hi))
		case !o.Positive && hi >= review:
			lines = append(lines, fmt.Sprintf("REVIEW    %-26s negative scored %.2f–%.2f", id, lo, hi))
		}
	}
	sort.Strings(lines)
	if len(lines) > 0 {
		fmt.Println("           " + strings.Join(lines, "\n           "))
	}
}
