package pushgate.commit

deny[msg] {
	not is_string(input.commithash)
	msg := "unreadable evidence: git commithash is missing"
}

deny[msg] {
	is_array(input.remotes)
	count(input.remotes) == 0
	msg := "no git remote recorded"
}
