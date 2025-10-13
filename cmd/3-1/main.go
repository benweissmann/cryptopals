package main

import (
	"crypto/aes"
	cryptoRand "crypto/rand"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/cbc"
	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

func main() {
	secrets := [][]byte{
		convert.MustParseBase64("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
		convert.MustParseBase64("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
		convert.MustParseBase64("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
		convert.MustParseBase64("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
		convert.MustParseBase64("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
		convert.MustParseBase64("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
		convert.MustParseBase64("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
		convert.MustParseBase64("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
		convert.MustParseBase64("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
		convert.MustParseBase64("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
	}

	key := make([]byte, 16)
	_, randErr := cryptoRand.Read(key)
	if randErr != nil {
		panic(randErr.Error())
	}

	blockCipher, aesErr := aes.NewCipher(key)
	if aesErr != nil {
		panic(aesErr.Error())
	}

	oracle := func(ciphertext []byte, iv []byte) (paddingValid bool) {
		blockMode := cbc.NewCBCDecrypter(blockCipher, iv)

		plaintext := make([]byte, len(ciphertext))
		blockMode.CryptBlocks(plaintext, ciphertext)

		_, ok := padding.VerifyPKCSPadding(plaintext)
		return ok
	}

	for _, secret := range secrets {
		paddedSecret := padding.PKCS7Pad(secret, blockCipher.BlockSize())
		iv := make([]byte, blockCipher.BlockSize())
		_, randErr := cryptoRand.Read(iv)
		if randErr != nil {
			panic(randErr.Error())
		}

		blockMode := cbc.NewCBCEncrypter(blockCipher, iv)
		ciphertext := make([]byte, len(paddedSecret))
		blockMode.CryptBlocks(ciphertext, paddedSecret)

		fmt.Println(string(cbc.PaddingOracle(blockCipher.BlockSize(), ciphertext, iv, oracle)))
	}
}
