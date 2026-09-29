package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aflock-ai/jevlint/internal/lint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var lintCmd = &cobra.Command{
	Use:   "lint <policy.json>",
	Short: "Lint one policy for meaning",
	Args:  cobra.ExactArgs(1),
	RunE:  runLint,
}

func init() {
	f := lintCmd.Flags()
	f.String("type", "", "policy flavor override: witness|cilock|pushgate")
	f.String("context", "", "one line about the repo; enables the over-scoped check")
	f.Bool("structural-only", false, "deterministic checks only (no key, no egress)")
	f.String("calibration", "", "calibration lock to take per-question thresholds from (default: the one built in); an explicit --min-prob overrides it")
	f.Int("batch-size", lint.DefaultBatchSize, "Rego modules merged into one Jev request (env JEVLINT_BATCH_SIZE). Default 1 is measured-safe; above 1 lowers underspecified-check recall — true positives fell from 0.72–0.92 to 0.26–0.76 — so prefer --concurrency for speed")
	f.Int("concurrency", lint.DefaultConcurrency, "Jev requests in flight at once (env JEVLINT_CONCURRENCY); speeds up a run without changing what Jev sees")
	_ = viper.BindPFlag("batch-size", f.Lookup("batch-size"))
	_ = viper.BindPFlag("concurrency", f.Lookup("concurrency"))
}

func runLint(cmd *cobra.Command, args []string) error {
	path := args[0]
	p, err := lint.LoadPolicy(path)
	if err != nil {
		return fmt.Errorf("cannot read policy: %w", err)
	}

	flavor, _ := cmd.Flags().GetString("type")
	if flavor == "" {
		flavor = p.Flavor()
	}
	structuralOnly, _ := cmd.Flags().GetBool("structural-only")
	repoContext, _ := cmd.Flags().GetString("context")
	asJSON := viper.GetBool("json")
	model := viper.GetString("model")
	minProb := viper.GetFloat64("min-prob")
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("--batch-size must be at least 1, got %d", batchSize)
	}
	concurrency := viper.GetInt("concurrency")
	if concurrency < 1 {
		return fmt.Errorf("--concurrency must be at least 1, got %d", concurrency)
	}

	findings := lint.StructuralChecks(p)
	var (
		c     *lint.Client
		th    lint.Thresholds
		notes []string
	)
	if !structuralOnly {
		c = lint.NewClient(model, viper.GetString("api-key"))
		if !c.HasKey() {
			return fmt.Errorf("no API key (TYPESAFE_API_KEY / JEVLINT_API_KEY / ~/.config/typesafe/api_key / keychain); use --structural-only to skip Jev")
		}
		if th, notes, err = resolveThresholds(cmd, effectiveModel(model), minProb); err != nil {
			return err
		}
		for _, n := range notes {
			fmt.Fprintln(os.Stderr, "jevlint: "+n)
		}
		findings = append(findings, lint.SemanticChecks(p, c, repoContext, th, batchSize, concurrency)...)
	}
	findings = lint.Dedupe(findings)

	cnc := lint.CountCNC(findings)
	review := lint.CountReview(findings)
	if asJSON {
		extra := map[string]any{}
		if c != nil {
			extra["jev"] = map[string]any{"requests": c.Requests(), "questions": c.Questions(), "batch_size": batchSize, "concurrency": concurrency}
			extra["thresholds"] = th
			if len(notes) > 0 {
				extra["calibration_notes"] = notes
			}
		}
		extra["review"] = review
		emitJSON(path, flavor, findings, cnc, extra)
	} else {
		mode := "structural + Jev (" + effectiveModel(model) + ")"
		if structuralOnly {
			mode = "structural only"
		}
		fmt.Printf("jevlint  %s\n  flavor: %s   mode: %s\n", path, flavor, mode)
		if len(findings) == 0 {
			fmt.Println("  clean — no issues found")
		} else {
			lint.Render(os.Stdout, findings)
		}
		summary := fmt.Sprintf("  %d finding(s), %d could-not-check", len(findings)-review, cnc)
		if review > 0 {
			summary += fmt.Sprintf(", %d to review", review)
		}
		fmt.Println(summary)
		if c != nil {
			fmt.Printf("  jev: %d request(s) for %d question(s), batch size %d, concurrency %d\n", c.Requests(), c.Questions(), batchSize, concurrency)
			fmt.Printf("  thresholds: %s\n", th.Source)
		}
	}

	if cnc > 0 {
		os.Exit(2)
	}
	// A REVIEW is shown but does not fail the run: it sits below the threshold
	// the corpus showed to be precise.
	if len(findings)-review > 0 {
		os.Exit(1)
	}
	return nil
}

// resolveThresholds picks what turns a Jev probability into a finding. An
// explicit --min-prob (flag, env or config) is a request for one threshold
// everywhere, and wins. Otherwise the calibration lock — --calibration, or the
// one compiled in — supplies per-question thresholds and review bands; a
// question it cannot vouch for falls back to --min-prob's value.
func resolveThresholds(cmd *cobra.Command, model string, minProb float64) (lint.Thresholds, []string, error) {
	if minProbExplicit(cmd) {
		return lint.Uniform(minProb), nil, nil
	}
	var (
		cal *lint.Calibration
		err error
	)
	if path, _ := cmd.Flags().GetString("calibration"); path != "" {
		cal, err = lint.ReadCalibration(path)
	} else {
		cal, err = lint.EmbeddedCalibration()
	}
	if err != nil {
		return lint.Thresholds{}, nil, fmt.Errorf("calibration lock: %w", err)
	}
	th, notes := cal.Thresholds(model, minProb)
	return th, notes, nil
}

func minProbExplicit(cmd *cobra.Command) bool {
	if f := cmd.Flag("min-prob"); f != nil && f.Changed {
		return true
	}
	if _, ok := os.LookupEnv("JEVLINT_MIN_PROB"); ok {
		return true
	}
	return viper.InConfig("min-prob")
}

func effectiveModel(m string) string {
	if m == "" {
		return lint.DefaultModel
	}
	return m
}

func emitJSON(path, flavor string, findings []lint.Finding, cnc int, extra map[string]any) {
	lint.Sort(findings)
	if findings == nil {
		findings = []lint.Finding{}
	}
	doc := map[string]any{
		"policy":          path,
		"flavor":          flavor,
		"findings":        findings,
		"could_not_check": cnc,
	}
	for k, v := range extra {
		doc[k] = v
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	fmt.Println(string(out))
}
