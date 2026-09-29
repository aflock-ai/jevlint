package neg0

deny[msg] {
	not is_string(input.commithash)
	msg := "missing commithash"
}
