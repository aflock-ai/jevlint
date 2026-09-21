package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/manzil-infinity180/jev-policy-lint/internal/lint"
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

	findings := lint.StructuralChecks(p)
	if !structuralOnly {
		c := lint.NewClient(model, viper.GetString("api-key"))
		if !c.HasKey() {
			return fmt.Errorf("no API key (TYPESAFE_API_KEY / JEVLINT_API_KEY / ~/.config/typesafe/api_key / keychain); use --structural-only to skip Jev")
		}
		findings = append(findings, lint.SemanticChecks(p, c, repoContext, minProb)...)
	}
	findings = lint.Dedupe(findings)

	cnc := lint.CountCNC(findings)
	if asJSON {
		emitJSON(path, flavor, findings, cnc)
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

func emitJSON(path, flavor string, findings []lint.Finding, cnc int) {
	lint.Sort(findings)
	if findings == nil {
		findings = []lint.Finding{}
	}
	out, _ := json.MarshalIndent(map[string]any{
		"policy":          path,
		"flavor":          flavor,
		"findings":        findings,
		"could_not_check": cnc,
	}, "", "  ")
	fmt.Println(string(out))
}
