package commandrun.cmd

deny[msg] {
	input.cmd != ["go", "build", "-o=testapp", "."]
	msg := "unexpected cmd"
}
