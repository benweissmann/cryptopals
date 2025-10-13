package main

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"math"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/ctr"
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
	shortestLength := math.MaxInt
	for i, plaintext := range plaintexts {
		ciphertexts[i] = make([]byte, len(plaintext))
		blockMode.CryptBlocks(ciphertexts[i], plaintext)

		if len(ciphertexts[i]) < shortestLength {
			shortestLength = len(ciphertexts[i])
		}
	}

	concat := []byte{}
	for _, ciphertext := range ciphertexts {
		concat = append(concat, ciphertext[0:shortestLength]...)
	}

	_, plaintext := xor.BreakRepeatingKeyXor(concat, shortestLength)
	fmt.Println(plaintext)
}
