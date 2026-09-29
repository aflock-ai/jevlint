package pushgate.commit

deny[msg] {
	not is_string(input.commithash)
	msg := "unreadable evidence: git commithash is missing"
}

# rendered without a binding — fires on every input, refuses everything
deny[msg] {
	msg := "policy document rendered without a commit binding"
}
