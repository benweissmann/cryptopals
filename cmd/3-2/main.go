package main

import (
	"crypto/aes"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/ctr"
)

func main() {
	ciphertext := convert.MustParseBase64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	key := "YELLOW SUBMARINE"

	blockCipher, aesErr := aes.NewCipher([]byte(key))
	if aesErr != nil {
		panic(aesErr.Error())
	}

	blockMode := ctr.NewCTRCrypter(blockCipher, 0)

	out := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(out, ciphertext)

	fmt.Println(string(out))
}
