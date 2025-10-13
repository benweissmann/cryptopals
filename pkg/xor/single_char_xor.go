package xor

import (
	"bytes"

	"github.com/benweissmann/cryptopals/pkg/plaintextscore"
)

func BreakSingleCharXor(ciphertext []byte) (plaintext string, key byte, score float64) {
	bestScore := -100.0
	bestKey := byte(0)
	bestPlaintext := ""

	for keyChr := byte(0); keyChr < 255; keyChr += 1 {
		key := bytes.Repeat([]byte{keyChr}, len(ciphertext))
		plaintextBytes := Xor(ciphertext, []byte(key))

		plaintext := string(plaintextBytes)
		score := plaintextscore.ScorePlaintextSimple(plaintext)

		if score > float64(bestScore) {
			bestScore = score
			bestKey = keyChr
			bestPlaintext = plaintext
		}
	}

	return bestPlaintext, bestKey, float64(bestScore)
}
