package main

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/cbc"
	"github.com/benweissmann/cryptopals/pkg/dh"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

func check(err error) {
	if err != nil {
		panic(err.Error())
	}
}

type message struct {
	ciphertext []byte
	iv         []byte
}

func encryptMessage(msg string, aesSession cipher.Block) *message {
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	check(err)

	mode := cbc.NewCBCEncrypter(aesSession, iv)

	msgBytes := padding.PKCS7Pad([]byte(msg), aesSession.BlockSize())
	ciphertext := make([]byte, len(msgBytes))
	mode.CryptBlocks(ciphertext, msgBytes)

	return &message{
		ciphertext: ciphertext,
		iv:         iv,
	}
}

func decryptMessage(message *message, aesSession cipher.Block) string {
	mode := cbc.NewCBCDecrypter(aesSession, message.iv)

	cleartext := make([]byte, len(message.ciphertext))
	mode.CryptBlocks(cleartext, message.ciphertext)

	return string(padding.PKCS7Unpad(cleartext))
}

func healthyProtocolExchange() {
	aKeypair, err := dh.GenerateKeypair()
	check(err)

	p, g := aKeypair.Params()
	aPublic := aKeypair.PubKey()

	// PartyA sends p, g, A to PartyB
	bKeypair, err := dh.GenerateKeypairWithParams(p, g)
	check(err)

	bPublic := bKeypair.PubKey()
	bSession := bKeypair.AESSession(aPublic)

	// PartyB sends B to PartyA
	aSession := aKeypair.AESSession(bPublic)

	// PartyA sends a message to PartyB
	aToBMessage := encryptMessage("Hello from A!", aSession)
	fmt.Println(decryptMessage(aToBMessage, bSession))

	// PartyB sends a message to PartyA
	bToAMessage := encryptMessage("Hello from B!", bSession)
	fmt.Println(decryptMessage(bToAMessage, aSession))
}

func mitmProtocolExchange() {
	aKeypair, err := dh.GenerateKeypair()
	check(err)

	p, g := aKeypair.Params()
	//aPublic := aKeypair.PubKey()

	// M acquires p, g, A
	// M swaps A for p
	tamperedAPublic := p

	// Party B instantiates its session with the tampered public key
	bKeypair, err := dh.GenerateKeypairWithParams(p, g)
	check(err)

	//bPublic := bKeypair.PubKey()
	bSession := bKeypair.AESSession(tamperedAPublic)

	// M acquires B
	// M swaps B for p
	tamperedBPublic := p
	aSession := aKeypair.AESSession(tamperedBPublic)

	// A and B can talk
	aToBMessage := encryptMessage("Hello from A!", aSession)
	fmt.Println(decryptMessage(aToBMessage, bSession))

	bToAMessage := encryptMessage("Hello from B!", bSession)
	fmt.Println(decryptMessage(bToAMessage, aSession))

	// M can intercept messages -- session key has been forced to 0
	// a's session = ((p swapped for B)**a) % p = 0
	// b's session = ((p swapped for A)**b) % p = 0
	mSession := dh.AESSessionFromSessionKey(big.NewInt(0))
	fmt.Printf("Intercepted: %s\n", decryptMessage(aToBMessage, mSession))
	fmt.Printf("Intercepted: %s\n", decryptMessage(bToAMessage, mSession))
}

func main() {
	fmt.Println("Healthy exchange")
	healthyProtocolExchange()

	fmt.Println("\n\nMITM exchange")
	mitmProtocolExchange()
}
