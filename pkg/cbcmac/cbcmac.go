package cbcmac

import (
	"crypto/aes"

	"github.com/benweissmann/cryptopals/pkg/cbc"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

func CBCMAC(plaintext []byte, iv []byte, key []byte) []byte {
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

	return ciphertext[len(ciphertext)-blockCipher.BlockSize():]
}
