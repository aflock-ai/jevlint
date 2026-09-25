package diary.pushtests

# The step is evidence only when the recorded command is readable and passed.

deny[msg] {
	not readable_exitcode
	msg := "unreadable evidence: command-run exitcode is missing or is not a number; this attestation cannot be judged"
}

readable_exitcode {
	is_number(input.exitcode)
}

deny[msg] {
	not readable_cmd
	msg := "unreadable evidence: command-run cmd is missing, is not a list, or is empty; this attestation cannot be judged"
}

readable_cmd {
	is_array(input.cmd)
	count(input.cmd) > 0
}

deny[msg] {
	is_number(input.exitcode)
	input.exitcode != 0
	msg := sprintf("the push-tests command exited %d: fix the failure it printed, then re-mint with: cilock run --step push-tests -a git -a alps-evidence -- <your test command>", [input.exitcode])
}
