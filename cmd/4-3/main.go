package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"net/url"
	"strings"

	"github.com/benweissmann/cryptopals/pkg/cbc"
	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/padding"
	"github.com/benweissmann/cryptopals/pkg/plaintextscore"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

func main() {
	key := []byte("YELLOW SUBMARINE")

	blockCipher, aesErr := aes.NewCipher(key)
	if aesErr != nil {
		panic(aesErr.Error())
	}

	generateSessionData := func(userdata string) (ciphertext []byte, iv []byte) {
		data := "comment1=cooking%20MCs;userdata=" + url.QueryEscape(userdata) + ";comment2=%20like%20a%20pound%20of%20bacon"
		plaintext := padding.PKCS7Pad([]byte(data), blockCipher.BlockSize())

		iv = key // don't do this

		blockMode := cbc.NewCBCEncrypter(blockCipher, iv)
		ciphertext = make([]byte, len(plaintext))

		blockMode.CryptBlocks(ciphertext, []byte(plaintext))

		return ciphertext, iv
	}

	isAdmin := func(session []byte, iv []byte) (bool, error) {
		blockMode := cbc.NewCBCDecrypter(blockCipher, iv)

		plaintext := make([]byte, len(session))
		blockMode.CryptBlocks(plaintext, session)

		if plaintextscore.HasHighAscii(plaintext) {
			return false, fmt.Errorf("Plaintext looks invalid: %x", plaintext)
		}

		sessionPlain, ok := padding.VerifyPKCSPadding(plaintext)
		if !ok {
			return false, fmt.Errorf("Padding error: %q", plaintext)
		}

		fmt.Println(string(sessionPlain))
		return strings.Contains(string(sessionPlain), ";admin=true;"), nil
	}

	session, iv := generateSessionData("xadminxtruexAAAAAAAAAA")

	// tamperedSession: C1, 0, C1
	tamperedSession := make([]byte, blockCipher.BlockSize()*3)
	copy(tamperedSession[0:blockCipher.BlockSize()], session[0:blockCipher.BlockSize()])
	copy(tamperedSession[blockCipher.BlockSize():blockCipher.BlockSize()*2], bytes.Repeat([]byte{0}, blockCipher.BlockSize()))
	copy(tamperedSession[blockCipher.BlockSize()*2:blockCipher.BlockSize()*3], session[0:blockCipher.BlockSize()])

	_, err := isAdmin(tamperedSession, iv)

	if err == nil {
		fmt.Printf("Did not fail :(")
		return
	}

	plaintextHex := err.Error()[len("Plaintext looks invalid: "):]
	plaintextBytes := convert.MustParseHex(plaintextHex)

	fmt.Println(
		string(
			xor.Xor(
				plaintextBytes[0:blockCipher.BlockSize()],
				plaintextBytes[blockCipher.BlockSize()*2:blockCipher.BlockSize()*3],
			),
		),
	)
}
