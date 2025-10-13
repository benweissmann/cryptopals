package main

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/cbc"
	"github.com/benweissmann/cryptopals/pkg/convert"
)

func main() {
	ciphertext := convert.MustLoadBase64Blob()

	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte{0}, 16)

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}

	cbcDecrypter := cbc.NewCBCDecrypter(cipher, iv)
	decrypted := make([]byte, len(ciphertext))
	cbcDecrypter.CryptBlocks(decrypted, ciphertext)

	fmt.Println(string(decrypted))
}
