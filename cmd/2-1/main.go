package main

import (
	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

func main() {
	in := []byte("YELLOW SUBMARINE")
	out := padding.PKCS7Pad(in, 20)

	convert.EscapedPrintBytes(out)
}
