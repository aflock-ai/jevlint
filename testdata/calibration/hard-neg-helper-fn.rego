package hard.neg.helper

deny[msg] {
	not trusted(input.builder.id)
	msg := "untrusted builder"
}

trusted(b) {
	b == "github-actions"
}
