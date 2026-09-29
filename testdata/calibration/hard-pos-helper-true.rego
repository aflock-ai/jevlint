package hard.pos.helper

enforced {
	true
}

deny[msg] {
	enforced
	msg := "release is frozen"
}
