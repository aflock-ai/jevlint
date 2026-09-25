// Package cmd wires the jevlint CLI: cobra for commands, viper for config and
// environment precedence — the same shape witness and cosign use.
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "jevlint",
	Short: "Lint witness / cilock / pushgate policies for meaning, not schema",
	Long: `jevlint checks what a policy MEANS, not just that it parses.

cilock policy validate tells you a policy is well-formed. jevlint tells you
whether it will refuse every push, admit every tenant, verify nothing, or
quietly got weaker than the last release.

Structural checks are deterministic and never fail open. Semantic checks are
typed judgments from TypeSafe Jev; a Jev call that cannot answer is reported,
never counted as a pass.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the CLI and sets the process exit code.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&cfgFile, "config", "", "config file (default $HOME/.config/jevlint/config.yaml)")
	pf.String("model", "", "Jev model (env JEVLINT_MODEL; default jev-1.13.0)")
	pf.Float64("min-prob", 0.70, "report a Jev finding at or above this probability for EVERY question (env JEVLINT_MIN_PROB). Unset, calibrated per-question thresholds apply and this is only the fallback for a question the calibration lock does not cover")
	pf.String("api-key", "", "TypeSafe API key (env TYPESAFE_API_KEY / JEVLINT_API_KEY; falls back to file and keychain)")
	pf.Bool("json", false, "machine-readable output")

	_ = viper.BindPFlag("model", pf.Lookup("model"))
	_ = viper.BindPFlag("min-prob", pf.Lookup("min-prob"))
	_ = viper.BindPFlag("api-key", pf.Lookup("api-key"))
	_ = viper.BindPFlag("json", pf.Lookup("json"))
	// TYPESAFE_API_KEY is the canonical name the whole toolchain uses; accept it
	// as well as the JEVLINT_-prefixed form.
	_ = viper.BindEnv("api-key", "TYPESAFE_API_KEY", "JEVLINT_API_KEY")

	rootCmd.AddCommand(lintCmd, diffCmd, calibrateCmd, versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else if home, err := os.UserHomeDir(); err == nil {
		viper.AddConfigPath(home + "/.config/jevlint")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}
	viper.SetEnvPrefix("JEVLINT")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	_ = viper.ReadInConfig() // absent config is fine
}
