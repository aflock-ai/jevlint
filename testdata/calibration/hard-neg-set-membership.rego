package hard.neg.set

allowed := {"github-actions", "gitlab-ci"}

deny[msg] {
	not allowed[input.builder.id]
	msg := "builder not allowed"
}
