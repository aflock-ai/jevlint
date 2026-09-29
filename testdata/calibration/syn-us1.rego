package us1

deny[msg] {
	count(input.findings) > 0
	msg := "secret findings present"
}

suppressed := input.suppressed_findings
