package neg3

deny[msg] {
	input.treeSize == 0
	msg := "the run recorded no product"
}
