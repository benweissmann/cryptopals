package main

import (
	"encoding/hex"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/xor"
)

func main() {
	in := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

	fmt.Println(hex.EncodeToString(xor.RepeatingKeyXor(in, "ICE")))
}
