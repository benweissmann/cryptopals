package main

import (
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

func main() {
	ciphertext := convert.MustParseHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	bestPlaintext, bestKey, bestScore := xor.BreakSingleCharXor(ciphertext)

	fmt.Printf("%s\nBest key: %c\nBest score: %f\n", bestPlaintext, bestKey, bestScore)
}
