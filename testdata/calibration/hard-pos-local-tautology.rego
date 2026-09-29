package hard.pos.local

deny[msg] {
	limit := 3
	limit == 3
	msg := sprintf("more than %d retries", [limit])
}
