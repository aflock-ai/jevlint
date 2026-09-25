package hard.us.signers

deny[msg] {
	count(input.signatures) == 0
	msg := "unsigned"
}

signer_keyids := {s.keyid | s := input.signatures[_]}
