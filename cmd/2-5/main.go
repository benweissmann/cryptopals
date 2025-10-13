package main

import (
	"crypto/aes"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/benweissmann/cryptopals/pkg/ecb"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

const key = "YELLOW SUBMARINE"

func buildProfileBlob(email string) []byte {
	plaintext := fmt.Sprintf(
		"email=%s&uid=10&role=user",
		url.QueryEscape(email),
	)

	fmt.Println(plaintext)

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}

	paddedPlaintext := padding.PKCS7Pad([]byte(plaintext), cipher.BlockSize())

	ecbEncrypter := ecb.NewECBEncrypter(cipher)
	encrypted := make([]byte, len(paddedPlaintext))
	ecbEncrypter.CryptBlocks(encrypted, []byte(paddedPlaintext))

	return encrypted
}

func verifyProfileBlob(blob []byte) url.Values {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}

	ecbDecrypter := ecb.NewECBDecrypter(cipher)

	decrypted := make([]byte, len(blob))
	ecbDecrypter.CryptBlocks(decrypted, blob)

	values, err := url.ParseQuery(string(decrypted))
	if err != nil {
		panic(err.Error())
	}

	return values
}

func main() {
	blob1 := buildProfileBlob("aaa@bar.com")
	blob2 := buildProfileBlob("aaaaaaaaaaadmin")

	constructedBlob := make([]byte, 16*3)
	copy(constructedBlob[0:16*2], blob1[0:16*2])
	copy(constructedBlob[16*2:16*3], blob2[16:16*2])

	decoded := verifyProfileBlob(constructedBlob)
	json, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(string(json))
}
