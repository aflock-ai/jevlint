package us3

deny[msg] {
	not is_array(input.binaries)
	msg := "binaries missing"
}

arch := input.binaries[0].settings.GOARCH
