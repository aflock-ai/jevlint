package hard.neg.iter

deny[msg] {
	some i
	input.findings[i].severity == "critical"
	msg := "critical finding present"
}
