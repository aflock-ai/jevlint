package hard.us.allowlist

allowed_builders := {"github-actions", "gitlab-ci"}

builder := input.builder.id

deny[msg] {
	not input.builder
	msg := "no builder recorded"
}
