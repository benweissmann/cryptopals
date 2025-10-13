package main

import (
	"crypto/aes"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"fmt"
	mathRand "math/rand/v2"

	"github.com/benweissmann/cryptopals/pkg/ecb"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

func main() {
	key := make([]byte, 16)
	_, randErr := cryptoRand.Read(key)
	if randErr != nil {
		panic(randErr.Error())
	}

	prefixLength := mathRand.N(10)
	prefix := make([]byte, prefixLength)
	_, randErr = cryptoRand.Read(prefix)
	if randErr != nil {
		panic(randErr.Error())
	}

	blockCipher, aesErr := aes.NewCipher(key)
	if aesErr != nil {
		panic(aesErr.Error())
	}

	blockMode := ecb.NewECBEncrypter(blockCipher)

	secret, decodeErr := base64.StdEncoding.DecodeString(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`)
	if decodeErr != nil {
		panic(decodeErr.Error())
	}

	oracle := func(plaintext []byte) []byte {
		paddedPlaintext := append([]byte{}, prefix...)
		paddedPlaintext = append(paddedPlaintext, plaintext...)
		paddedPlaintext = append(paddedPlaintext, secret...)
		paddedPlaintext = padding.PKCS7Pad(paddedPlaintext, blockCipher.BlockSize())

		ciphertext := make([]byte, len(paddedPlaintext))
		blockMode.CryptBlocks(ciphertext, paddedPlaintext)

		return ciphertext
	}

	plaintext := ecb.BreakECBFromOracleWithAttackerControlledMiddle(oracle)
	fmt.Println(string(plaintext))
}
