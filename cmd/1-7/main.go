package main

import (
	"crypto/aes"
	"fmt"
	"os"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/ecb"
)

func main() {
	dat, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Print(err.Error())
		return
	}

	ciphertext := convert.MustParseBase64(string(dat))

	key := "YELLOW SUBMARINE"

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}

	ecbDecrypter := ecb.NewECBDecrypter(cipher)
	out := make([]byte, len(ciphertext))
	ecbDecrypter.CryptBlocks(out, ciphertext)

	fmt.Println(string(out))
}
