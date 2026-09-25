package p

deny[msg] {
	not is_string(input.commithash)
	msg := "missing commithash"
}

deny[msg] {
	bad_exit
	msg := "nonzero exit"
}

bad_exit {
	input.exitcode != 0
}
