package ecb_test

import (
	"crypto/aes"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/ecb"
)

func TestEcbDecryption(t *testing.T) {
	plaintext := "Lorem ipsum dolor sit amet, consectetur adipiscing elit........."
	key := "YELLOW SUBMARINE"

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}

	ecbEncrypter := ecb.NewECBEncrypter(cipher)
	ecbDecrypter := ecb.NewECBDecrypter(cipher)

	encrypted := make([]byte, len(plaintext))
	ecbEncrypter.CryptBlocks(encrypted, []byte(plaintext))

	decrypted := make([]byte, len(plaintext))
	ecbDecrypter.CryptBlocks(decrypted, encrypted)

	if string(decrypted) != plaintext {
		t.Fatalf("Got %s, expected %s", string(decrypted), plaintext)
	}
}
