package main

import (
	"fmt"
	"os"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

func main() {
	dat, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Print(err.Error())
		return
	}

	ciphertext := convert.MustParseBase64(string(dat))

	keysize := xor.GetRepeatingKeyXorKeySize(ciphertext)
	fmt.Printf("Likely keysize: %d\n", keysize)

	key, plaintext := xor.BreakRepeatingKeyXor(ciphertext, 29)
	fmt.Printf("Key: %s\nPlaintext:\n%s", key, plaintext)
}
