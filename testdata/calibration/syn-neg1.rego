package neg1

deny[msg] {
	is_number(input.exitcode)
	input.exitcode != 0
	msg := sprintf("command exited %d", [input.exitcode])
}
