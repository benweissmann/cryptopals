package main

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/ctr"
	"github.com/benweissmann/cryptopals/pkg/plaintextscore"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

func main() {
	plaintexts := convert.MustLoadBas64Lines()

	key := make([]byte, 16)
	_, randErr := rand.Read(key)
	if randErr != nil {
		panic(randErr.Error())
	}

	blockCipher, aesErr := aes.NewCipher(key)
	if aesErr != nil {
		panic(aesErr.Error())
	}

	blockMode := ctr.NewCTRCrypter(blockCipher, 0)

	ciphertexts := make([][]byte, len(plaintexts))
	var longestCiphertext []byte
	for i, plaintext := range plaintexts {
		ciphertexts[i] = make([]byte, len(plaintext))
		blockMode.CryptBlocks(ciphertexts[i], plaintext)

		if len(ciphertexts[i]) > len(longestCiphertext) {
			longestCiphertext = ciphertexts[i]
		}
	}

	plaintextGuess := []byte(strings.Repeat("e", len(longestCiphertext)))

	for i := 0; i < len(plaintextGuess); i++ {
		bestGuess := byte(0)
		bestGuessScore := 0.0

		for c := 0; c < 256; c++ {
			plaintextGuess[i] = byte(c)
			keyStream := xor.Xor(plaintextGuess, longestCiphertext)

			totalScore := 0.0
			for _, ciphertext := range ciphertexts {
				plaintext := xor.Xor(ciphertext, keyStream[0:len(ciphertext)])
				totalScore += plaintextscore.ScorePlaintextSimple(string(plaintext))
			}

			if totalScore > bestGuessScore {
				bestGuessScore = totalScore
				bestGuess = byte(c)
			}
		}

		plaintextGuess[i] = bestGuess
	}

	keyStream := xor.Xor(plaintextGuess, longestCiphertext)
	for _, ciphertext := range ciphertexts {
		fmt.Printf("%q\n", xor.Xor(ciphertext, keyStream[0:len(ciphertext)]))
	}
}
