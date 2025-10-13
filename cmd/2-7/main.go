package main

import (
	"bytes"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/padding"
)

func main() {
	valid := []byte("ICE ICE BABY\x04\x04\x04\x04")
	expected := []byte("ICE ICE BABY")

	output, ok := padding.VerifyPKCSPadding(valid)
	if !ok {
		panic(fmt.Sprintf("Failed verification: %v", valid))
	}
	if !bytes.Equal(output, expected) {
		panic(fmt.Sprintf("Unpad failed: got %v, expected %v", output, expected))
	}

	_, ok = padding.VerifyPKCSPadding([]byte("ICE ICE BABY\x05\x05\x05\x05"))
	if ok {
		panic(fmt.Sprintf("Did not detect bad padding (case 1)"))
	}

	_, ok = padding.VerifyPKCSPadding([]byte("ICE ICE BABY\x01\x02\x03\x04"))
	if ok {
		panic(fmt.Sprintf("Did not detect bad padding (case 2)"))
	}

	fmt.Println("pass")
}
