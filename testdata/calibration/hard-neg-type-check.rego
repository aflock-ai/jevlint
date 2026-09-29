package hard.neg.type

deny[msg] {
	input.type != "https://slsa.dev/provenance/v1"
	msg := "wrong predicate type"
}
