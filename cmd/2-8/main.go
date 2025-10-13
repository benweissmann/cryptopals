package main

import (
	"crypto/aes"
	cryptoRand "crypto/rand"
	"fmt"
	"net/url"
	"strings"

	"github.com/benweissmann/cryptopals/pkg/cbc"
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

	generateSessionData := func(userdata string) (ciphertext []byte, iv []byte) {
		data := "comment1=cooking%20MCs;userdata=" + url.QueryEscape(userdata) + ";comment2=%20like%20a%20pound%20of%20bacon"
		plaintext := padding.PKCS7Pad([]byte(data), blockCipher.BlockSize())

		iv = make([]byte, 16)
		_, randErr := cryptoRand.Read(iv)
		if randErr != nil {
			panic(randErr.Error())
		}

		blockMode := cbc.NewCBCEncrypter(blockCipher, iv)
		ciphertext = make([]byte, len(plaintext))

		blockMode.CryptBlocks(ciphertext, []byte(plaintext))

		return ciphertext, iv
	}

	isAdmin := func(session []byte, iv []byte) bool {
		blockMode := cbc.NewCBCDecrypter(blockCipher, iv)

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

	session[16] = session[16] ^ ('x' ^ ';')
	session[22] = session[22] ^ ('x' ^ '=')
	session[27] = session[27] ^ ('x' ^ ';')

	win := isAdmin(session, iv)

	if win {
		fmt.Println("Success!")
	} else {
		fmt.Println("Failed :(")
	}
}
