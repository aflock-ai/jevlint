// jevlint lints a witness / cilock / pushgate policy for meaning, not schema:
// unconditional denials, wildcard functionaries, missing trust anchors, and —
// between two versions — silent weakening of the gate.
package main

import "github.com/manzil-infinity180/jev-policy-lint/cmd"

func main() { cmd.Execute() }
