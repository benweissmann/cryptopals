package main

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"fmt"
	mathRand "math/rand/v2"

	"github.com/benweissmann/cryptopals/pkg/cbc"
	"github.com/benweissmann/cryptopals/pkg/ecb"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

func oracle(plaintext []byte) []byte {
	key := make([]byte, 16)
	_, randErr := cryptoRand.Read(key)
	if randErr != nil {
		panic(randErr.Error())
	}

	blockCipher, aesErr := aes.NewCipher(key)
	if aesErr != nil {
		panic(aesErr.Error())
	}

	var blockMode cipher.BlockMode
	if mathRand.N(2) == 0 {
		fmt.Println("Using ECB")
		blockMode = ecb.NewECBEncrypter(blockCipher)
	} else {
		fmt.Println("Using CBC")

		iv := make([]byte, 16)
		_, ivErr := cryptoRand.Read(iv)
		if ivErr != nil {
			panic(ivErr.Error())
		}

		blockMode = cbc.NewCBCEncrypter(blockCipher, iv)
	}

	startPadding := make([]byte, mathRand.N(6)+5)
	_, randErr = cryptoRand.Read(startPadding)
	if randErr != nil {
		panic(randErr.Error())
	}

	endPadding := make([]byte, mathRand.N(6)+5)
	_, randErr = cryptoRand.Read(endPadding)
	if randErr != nil {
		panic(randErr.Error())
	}

	paddedPlaintext := startPadding
	paddedPlaintext = append(paddedPlaintext, plaintext...)
	paddedPlaintext = append(paddedPlaintext, endPadding...)
	paddedPlaintext = padding.PKCS7Pad(paddedPlaintext, blockCipher.BlockSize())

	ciphertext := make([]byte, len(paddedPlaintext))
	blockMode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext
}

func main() {
	for i := 0; i < 10; i++ {
		result := ecb.DetectEcbFromOracle(oracle)
		if result {
			fmt.Println("  Detected ECB")
		} else {
			fmt.Println("  Detected CBC")
		}
	}
}
