package main

import (
	"encoding/hex"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/ecb"
)

func main() {
	ciphertexts := convert.MustLoadHexLines()

	index, ciphertext, nRepeatedBlocks := ecb.DetectEcb(ciphertexts)

	fmt.Printf("Detected ECB at index %d (%d repeated blocks): %s\n", index, nRepeatedBlocks, hex.EncodeToString((ciphertext)))
}
