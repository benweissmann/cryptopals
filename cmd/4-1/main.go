package main

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/ctr"
	"github.com/benweissmann/cryptopals/pkg/ecb"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

func recoverPlaintext(
	ciphertext []byte,
	edit func(ciphertext []byte, offset int, newCleartext []byte) []byte,
) []byte {
	// ciphertext := keystream ^ plaintext
	// newCiphertext  := keystream ^ newPlaintext
	//
	// ciphertext ^ newCiphertext = plaintext ^ newPlaintext
	//
	// (plaintext ^ newPlaintext) ^ newPlaintext = plaintext

	newPlaintext := bytes.Repeat([]byte{'X'}, len(ciphertext))
	newCiphertext := edit(ciphertext, 0, newPlaintext)

	return xor.Xor(xor.Xor(newCiphertext, ciphertext), newPlaintext)
}

func main() {
	cbcCiphertext := convert.MustLoadBase64Blob()

	key := "YELLOW SUBMARINE"

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}

	ecbDecrypter := ecb.NewECBDecrypter(cipher)
	plaintext := make([]byte, len(cbcCiphertext))
	ecbDecrypter.CryptBlocks(plaintext, cbcCiphertext)

	crypter := ctr.NewCTRCrypter(cipher, 1000)
	ciphertext := make([]byte, len(plaintext))
	crypter.CryptBlocks(ciphertext, plaintext)

	edit := func(ciphertext []byte, offset int, newCleartext []byte) []byte {
		newCiphertext := make([]byte, len(ciphertext))
		copy(newCiphertext, ciphertext)

		crypter.Edit(newCiphertext, offset, newCleartext)

		return newCiphertext
	}

	fmt.Println(string(recoverPlaintext(ciphertext, edit)))
}
