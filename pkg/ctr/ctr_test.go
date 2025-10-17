package ctr

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

func TestCTR(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	crypter := NewCTRCrypter(
		cipher,
		RandomIV(),
	)

	input := []byte("this is a test of the CTR system. It's longer than a block.")
	output := make([]byte, len(input))

	crypter.CryptBlocks(output, input)
	fmt.Printf("Input (%d): %x\nOutput (%d): %x\n", len(input), input, len(output), output)

	if bytes.Equal(input, output) {
		t.Fatalf("Did not encrypt")
	}

	decrypted := make([]byte, len(input))
	crypter.CryptBlocks(decrypted, output)
	fmt.Printf("Decrypted: %x\n", decrypted)

	if !bytes.Equal(decrypted, input) {
		t.Fatalf("Did not decrypt")
	}
}
