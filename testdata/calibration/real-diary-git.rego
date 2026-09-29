package diary.pushtests.git

# The evidence must describe a verified, exact commit and a clean worktree,
# otherwise the tree the command read is not the tree the commit carries.

deny[msg] {
	not readable_git_commit
	msg := "unreadable evidence: git commit hash is missing or is not a string; this attestation cannot be judged"
}

readable_git_commit {
	is_string(input.commithash)
}

deny[msg] {
	not readable_git_marker
	msg := "unreadable evidence: verified git commit marker is missing or is not a boolean; this attestation cannot be judged"
}

readable_git_marker {
	is_boolean(input.commithashverified)
}

readable_status {
	is_object(object.get(input, "status", {}))
}

deny[msg] {
	not readable_status
	msg := "unreadable evidence: git status is not an object; this attestation cannot be judged"
}

deny[msg] {
	is_boolean(input.commithashverified)
	not input.commithashverified
	msg := "git attestor did not affirm that it resolved and verified HEAD"
}

deny[msg] {
	is_string(input.commithash)
	not regex.match("^[0-9a-f]{40}$", input.commithash)
	msg := "git attestor did not record an exact lowercase commit hash"
}

deny[msg] {
	status := object.get(input, "status", {})
	is_object(status)
	count(status) > 0
	msg := sprintf("push-tests ran with %d dirty worktree path(s): commit or stash, then re-mint with: cilock run --step push-tests -a git -a alps-evidence -- <your test command>", [count(status)])
}
