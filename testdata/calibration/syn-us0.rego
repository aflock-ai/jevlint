package us0

deny[msg] {
	input.summary.failed > 0
	msg := sprintf("%d failed", [input.summary.failed])
}

seen_errors := input.summary.errors
