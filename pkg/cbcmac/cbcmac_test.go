package cbcmac

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/cbc"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

func TestCBCMac(t *testing.T) {
	plaintext := []byte("hello world this needs to be longer than a single block")
	iv := bytes.Repeat([]byte{0x01}, 16)
	key := bytes.Repeat([]byte{0x02}, 16)

	// encrypt
	blockCipher, aesErr := aes.NewCipher(key)
	if aesErr != nil {
		panic(aesErr.Error())
	}

	encrypter := cbc.NewCBCEncrypter(
		blockCipher,
		iv,
	)

	msgBytes := padding.PKCS7Pad(plaintext, blockCipher.BlockSize())

	ciphertext := make([]byte, len(msgBytes))
	encrypter.CryptBlocks(ciphertext, msgBytes)

	fmt.Printf("Ciphertext: %x\n", ciphertext)

	mac := CBCMAC(plaintext, iv, key)
	fmt.Printf("MAC: %x\n", mac)

	if !bytes.Equal(ciphertext[48:], mac) {
		t.Fatalf("Expected: %x\nGot     : %x\n", ciphertext[48:], mac)
	}
}
