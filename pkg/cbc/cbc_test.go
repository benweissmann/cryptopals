package cbc_test

import (
	"crypto/aes"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/cbc"
)

func TestCbc(t *testing.T) {
	plaintext := "Lorem ipsum dolor sit amet, consectetur adipiscing elit........."
	iv := []byte("ABCDEFGHIJKLMNOP")
	key := "YELLOW SUBMARINE"

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}

	cbcEncrypter := cbc.NewCBCEncrypter(cipher, iv)
	cbcDecrypter := cbc.NewCBCDecrypter(cipher, iv)

	encrypted := make([]byte, len(plaintext))
	cbcEncrypter.CryptBlocks(encrypted, []byte(plaintext))

	decrypted := make([]byte, len(plaintext))
	cbcDecrypter.CryptBlocks(decrypted, encrypted)

	if string(decrypted) != plaintext {
		t.Fatalf("Got %s, expected %s", string(decrypted), plaintext)
	}
}
