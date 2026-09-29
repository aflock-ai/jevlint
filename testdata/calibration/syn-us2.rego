package us2

deny[msg] {
	input.exitcode != 0
	msg := sprintf("exited %d", [input.exitcode])
}

timed_out := input.timed_out
