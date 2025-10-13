package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

func main() {
	dat, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Print(err.Error())
		return
	}

	lines := strings.Split(string(dat), "\n")

	ciphertexts := [][]byte{}
	for _, line := range lines {
		cleanedLine := strings.TrimSpace(line)
		if len(cleanedLine) > 0 {
			ciphertexts = append(ciphertexts, convert.MustParseHex(cleanedLine))
		}
	}

	bestScore := 0.0
	bestPlaintext := ""
	bestCiphertext := ""
	bestKey := byte(0)

	for _, ciphertext := range ciphertexts {
		plaintext, key, score := xor.BreakSingleCharXor(ciphertext)
		if score > bestScore {
			bestScore, bestPlaintext, bestCiphertext, bestKey = score, plaintext, hex.EncodeToString(ciphertext), key
		}
	}

	fmt.Printf("%s (score %f with key %c from ciphertext %s)\n", bestPlaintext, bestScore, bestKey, bestCiphertext)
}
