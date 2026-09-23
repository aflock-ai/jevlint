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
	var c *lint.Client
	if !structuralOnly {
		c = lint.NewClient(model, viper.GetString("api-key"))
		if !c.HasKey() {
			return fmt.Errorf("no API key (TYPESAFE_API_KEY / JEVLINT_API_KEY / ~/.config/typesafe/api_key / keychain); use --structural-only to skip Jev")
		}
		findings = append(findings, lint.SemanticChecks(p, c, repoContext, minProb, batchSize, concurrency)...)
	}
	findings = lint.Dedupe(findings)

	cnc := lint.CountCNC(findings)
	if asJSON {
		extra := map[string]any{}
		if c != nil {
			extra["jev"] = map[string]any{"requests": c.Requests(), "questions": c.Questions(), "batch_size": batchSize, "concurrency": concurrency}
		}
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
		fmt.Printf("  %d finding(s), %d could-not-check\n", len(findings), cnc)
		if c != nil {
			fmt.Printf("  jev: %d request(s) for %d question(s), batch size %d, concurrency %d\n", c.Requests(), c.Questions(), batchSize, concurrency)
		}
	}

	if cnc > 0 {
		os.Exit(2)
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
	return nil
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
