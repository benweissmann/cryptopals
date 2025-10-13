package xor

import "fmt"

func Xor(a []byte, b []byte) []byte {
	if len(a) != len(b) {
		panic(fmt.Sprintf("Unequal buffer lengths: %d and %d", len(a), len(b)))
	}

	out := make([]byte, len(a))
	for i, aByte := range a {
		bByte := b[i]

		out[i] = aByte ^ bByte
	}

	return out
}
