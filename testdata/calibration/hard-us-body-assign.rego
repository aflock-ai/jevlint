package hard.us.body

deny[msg] {
	input.exitcode != 0
	cmd := input.cmd
	msg := sprintf("command exited %d", [input.exitcode])
}
