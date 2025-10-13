package main

import (
	"crypto/aes"
	cryptoRand "crypto/rand"
	"fmt"
	"net/url"
	"strings"

	"github.com/benweissmann/cryptopals/pkg/ctr"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

func main() {
	key := make([]byte, 16)
	_, randErr := cryptoRand.Read(key)
	if randErr != nil {
		panic(randErr.Error())
	}

	blockCipher, aesErr := aes.NewCipher(key)
	if aesErr != nil {
		panic(aesErr.Error())
	}

	generateSessionData := func(userdata string) (ciphertext []byte, iv uint64) {
		data := "comment1=cooking%20MCs;userdata=" + url.QueryEscape(userdata) + ";comment2=%20like%20a%20pound%20of%20bacon"
		plaintext := padding.PKCS7Pad([]byte(data), blockCipher.BlockSize())

		iv = ctr.RandomIV()

		blockMode := ctr.NewCTRCrypter(blockCipher, iv)
		ciphertext = make([]byte, len(plaintext))

		blockMode.CryptBlocks(ciphertext, []byte(plaintext))

		return ciphertext, iv
	}

	isAdmin := func(session []byte, iv uint64) bool {
		blockMode := ctr.NewCTRCrypter(blockCipher, iv)

		plaintext := make([]byte, len(session))
		blockMode.CryptBlocks(plaintext, session)

		sessionPlain, ok := padding.VerifyPKCSPadding(plaintext)
		if !ok {
			panic(fmt.Sprintf("Padding error: %q", plaintext))
		}

		fmt.Println(string(sessionPlain))

		return strings.Contains(string(sessionPlain), ";admin=true;")
	}

	session, iv := generateSessionData("xadminxtruexAAAAAAAAAA")

	session[32] = session[32] ^ ('x' ^ ';')
	session[38] = session[38] ^ ('x' ^ '=')
	session[43] = session[43] ^ ('x' ^ ';')

	win := isAdmin(session, iv)

	if win {
		fmt.Println("Success!")
	} else {
		fmt.Println("Failed :(")
	}
}
