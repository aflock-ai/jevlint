package neg2

deny[msg] {
	input.summary.failed > 0
	msg := "tests failed"
}

deny[msg] {
	input.summary.errors > 0
	msg := "tests errored"
}
