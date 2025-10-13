package ctr

import (
	"crypto/aes"
	"fmt"
	"testing"
)

func TestCtrEdit(t *testing.T) {
	plaintext := "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
	key := "YELLOW SUBMARINE"

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}

	crypter := NewCTRCrypter(cipher, 1000)
	ciphertext := make([]byte, len(plaintext))
	crypter.CryptBlocks(ciphertext, []byte(plaintext))

	plaintext1 := make([]byte, len(plaintext))
	crypter.CryptBlocks(plaintext1, ciphertext)

	fmt.Println(string(plaintext1))
	if string(plaintext1) != plaintext {
		t.FailNow()
	}

	crypter.Edit(ciphertext, 28, []byte("YELLOW SUBMARINE......"))

	plaintext2 := make([]byte, len(plaintext))
	crypter.CryptBlocks(plaintext2, ciphertext)

	fmt.Println(string(plaintext2))
	if string(plaintext2) != "Lorem ipsum dolor sit amet, YELLOW SUBMARINE...... elit" {
		t.FailNow()
	}
}
