package hard.pos.defaulted

default blocked = true

deny[msg] {
	blocked
	msg := "pushes are blocked"
}
