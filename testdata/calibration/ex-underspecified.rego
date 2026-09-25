package p

# reads summary.errors but never denies on it, so a suite that ERRORED can still pass
deny[msg] {
	input.summary.failed > 0
	msg := sprintf("%d failed", [input.summary.failed])
}

seen_errors := input.summary.errors
