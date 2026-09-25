package pos2

deny[msg] {
	x := "placeholder"
	msg := sprintf("no binding for %v", [x])
}
