package ecb

import "bytes"

func DetectBlockSizeFromOracle(oracle func(plaintext []byte) []byte) int {
	firstBreakpoint := -1

	lastLen := len(oracle([]byte{}))
	for i := 1; ; i++ {
		plaintext := bytes.Repeat([]byte{0}, i)
		outLen := len(oracle(plaintext))

		if outLen != lastLen {
			if firstBreakpoint == -1 {
				firstBreakpoint = i
			} else {
				return i - firstBreakpoint
			}
		}

		lastLen = outLen
	}
}
