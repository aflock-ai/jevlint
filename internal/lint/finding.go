package lint

import (
	"fmt"
	"io"
	"sort"
)

const (
	High    = "HIGH"
	Medium  = "MEDIUM"
	Low     = "LOW"
	Unknown = "UNKNOWN"
)

// Finding is one issue. Fix is the concrete remediation; Prob is set only for
// Jev-backed findings so a reader can tell a judgment from a fact.
type Finding struct {
	Severity string  `json:"severity"`
	Check    string  `json:"check"`
	Location string  `json:"location"`
	Message  string  `json:"message"`
	Fix      string  `json:"fix,omitempty"`
	Prob     float64 `json:"probability,omitempty"`
}

var sevRank = map[string]int{High: 0, Medium: 1, Unknown: 2, Low: 3}

// Sort orders findings most-severe first, stably.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		return sevRank[fs[i].Severity] < sevRank[fs[j].Severity]
	})
}

// Render writes findings as text to w.
func Render(w io.Writer, fs []Finding) {
	Sort(fs)
	for _, f := range fs {
		fmt.Fprintf(w, "  %-7s %-22s %s\n", f.Severity, f.Check, f.Location)
		fmt.Fprintf(w, "          %s\n", f.Message)
		if f.Fix != "" {
			fmt.Fprintf(w, "          fix: %s\n", f.Fix)
		}
	}
}

// Dedupe drops repeat (check, location) pairs, keeping the first — so a
// deterministic finding wins over a later Jev one for the same issue.
func Dedupe(fs []Finding) []Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		k := f.Check + "|" + f.Location
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// CountCNC returns how many findings are could-not-check (Jev gave no answer).
func CountCNC(fs []Finding) int {
	n := 0
	for _, f := range fs {
		if f.Check == "could-not-check" {
			n++
		}
	}
	return n
}
