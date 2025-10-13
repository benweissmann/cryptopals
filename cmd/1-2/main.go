package main

import (
	"encoding/hex"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

func main() {
	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"

	outBytes := xor.Xor(convert.MustParseHex(in1), convert.MustParseHex(in2))

	out := hex.EncodeToString((outBytes))

	fmt.Print(out)
}
