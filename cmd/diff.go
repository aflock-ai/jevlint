package cmd

import (
	"fmt"
	"os"

	"github.com/manzil-infinity180/jev-policy-lint/internal/lint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var diffCmd = &cobra.Command{
	Use:   "diff <old.json> <new.json>",
	Short: "Flag where a new policy is weaker than the old one",
	Args:  cobra.ExactArgs(2),
	RunE:  runDiff,
}

func runDiff(cmd *cobra.Command, args []string) error {
	oldP, err := lint.LoadPolicy(args[0])
	if err != nil {
		return fmt.Errorf("cannot read old policy: %w", err)
	}
	newP, err := lint.LoadPolicy(args[1])
	if err != nil {
		return fmt.Errorf("cannot read new policy: %w", err)
	}
	findings := lint.DiffPolicies(oldP, newP)
	if viper.GetBool("json") {
		emitJSON(args[1], newP.Flavor(), findings, 0)
	} else {
		fmt.Printf("jevlint diff  %s -> %s\n", args[0], args[1])
		if len(findings) == 0 {
			fmt.Println("  no weakening detected")
		} else {
			lint.Render(os.Stdout, findings)
		}
		fmt.Printf("  %d weakening(s)\n", len(findings))
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
	return nil
}
