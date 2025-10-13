package hamming

import (
	"fmt"
	"math/bits"
)

func Distance(a []byte, b []byte) int {
	if len(a) != len(b) {
		panic(fmt.Sprintf("Unequal byte lengths passed to Distance: %d and %d", len(a), len(b)))
	}

	dist := 0
	for i := range a {
		dist += DifferingBits(a[i], b[i])
	}

	return dist
}

func DifferingBits(a byte, b byte) int {
	return bits.OnesCount8(a ^ b)
}
