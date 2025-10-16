package bleichenbacheroracle

import "math/big"

var one = big.NewInt(1)
var two = big.NewInt(2)
var three = big.NewInt(3)

func lt(a *big.Int, b *big.Int) bool {
	return a.Cmp(b) == -1
}

func lte(a *big.Int, b *big.Int) bool {
	return a.Cmp(b) != 1
}

func gt(a *big.Int, b *big.Int) bool {
	return a.Cmp(b) == 1
}

func floorDiv(a *big.Int, b *big.Int) *big.Int {
	return (&big.Int{}).Div(a, b)
}

func ceilDiv(a *big.Int, b *big.Int) *big.Int {
	r := (&big.Int{}).Add(a, b)
	r.Sub(r, one)
	return r.Div(r, b)
}

func min(a *big.Int, b *big.Int) *big.Int {
	if lt(a, b) {
		return a
	}

	return b
}

func max(a *big.Int, b *big.Int) *big.Int {
	if gt(a, b) {
		return a
	}

	return b
}
