package main

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/cbc"
	"github.com/benweissmann/cryptopals/pkg/dh"
	"github.com/benweissmann/cryptopals/pkg/padding"
	"github.com/benweissmann/cryptopals/pkg/plaintextscore"
)

/*
a's session = ((g**b % p) ** a) % p


g = 1
a's session = ((g**b % p) ** a) % p
  = ((1 % p) ** a) % p
  = (1 ** a) % p
  = 1 % p
  = 1


g = p
a's session = ((p**b % p) ** a) % p
  = (0 ** a) % p
  = 0 % p
  = 0

g = p - 1
a's session = (((p - 1)**b % p) ** a) % p
consider each step of modular exponentiation to compute c = (p-1) ** b
  c = 1
  for b' := range b:
	  c = c * (p-1) % p
	return c

	first step:
	  c = 1 * (p-1) % p
		c = p-1 % p
		c = p-1

	second step:
	  c = (p-1) * (p-1) % p
		c = p**2 - 2p + 1 % p
		c = p(p-2) + 1 % p
		c = (0, or -p if p<2) + 1 % p
		c = 1 or p-1

	by induction, c remains 1 or p-1

a's session = (((p - 1)**b % p) ** a) % p
  = ((1 or p-1) ** a) % p
	= 1 or p-1
*/

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

func decryptMessage(message *message, aesSession cipher.Block) (string, bool) {
	mode := cbc.NewCBCDecrypter(aesSession, message.iv)

	cleartext := make([]byte, len(message.ciphertext))
	mode.CryptBlocks(cleartext, message.ciphertext)

	unpad, ok := padding.VerifyPKCSPadding(cleartext)
	if !ok {
		return "", false
	}

	if plaintextscore.HasHighAscii(unpad) {
		return "", false
	}

	return string(unpad), true
}

func mustDecryptMessage(message *message, aesSession cipher.Block) string {
	dec, ok := decryptMessage(message, aesSession)

	if !ok {
		panic("Could not decrypt message")
	}

	return dec
}

// g = 1
func mitmProtocolExchangeG1() {
	aKeypair, err := dh.GenerateKeypairWithParams(dh.DefaultP, big.NewInt(1))
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
	fmt.Println(mustDecryptMessage(aToBMessage, bSession))

	// PartyB sends a message to PartyA
	bToAMessage := encryptMessage("Hello from B!", bSession)
	fmt.Println(mustDecryptMessage(bToAMessage, aSession))

	// M can intercept messages -- session key has been forced to 1
	mSession := dh.AESSessionFromSessionKey(big.NewInt(1))
	fmt.Printf("Intercepted: %s\n", mustDecryptMessage(aToBMessage, mSession))
	fmt.Printf("Intercepted: %s\n", mustDecryptMessage(bToAMessage, mSession))
}

// g = p
func mitmProtocolExchangeGEqualsP() {
	aKeypair, err := dh.GenerateKeypairWithParams(dh.DefaultP, dh.DefaultP)
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
	fmt.Println(mustDecryptMessage(aToBMessage, bSession))

	// PartyB sends a message to PartyA
	bToAMessage := encryptMessage("Hello from B!", bSession)
	fmt.Println(mustDecryptMessage(bToAMessage, aSession))

	// M can intercept messages -- session key has been forced to 0
	mSession := dh.AESSessionFromSessionKey(big.NewInt(0))
	fmt.Printf("Intercepted: %s\n", mustDecryptMessage(aToBMessage, mSession))
	fmt.Printf("Intercepted: %s\n", mustDecryptMessage(bToAMessage, mSession))
}

// g = p - 1
func mitmProtocolExchangeGEqualsPMinusOne() {
	pMinusOne := big.Int{}
	pMinusOne.Sub(dh.DefaultP, big.NewInt(1))
	aKeypair, err := dh.GenerateKeypairWithParams(dh.DefaultP, &pMinusOne)
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

	// M can intercept messages -- session key has been forced to 1
	mSession := dh.AESSessionFromSessionKey(big.NewInt(1))

	_, ok := decryptMessage(aToBMessage, mSession)
	if !ok {
		fmt.Println("Not 1; trying p-1")
		mSession = dh.AESSessionFromSessionKey(&pMinusOne)
	}

	fmt.Printf("Intercepted: %s\n", mustDecryptMessage(aToBMessage, mSession))
	fmt.Printf("Intercepted: %s\n", mustDecryptMessage(bToAMessage, mSession))
}

func main() {
	fmt.Println("\n\ng=1 exchange")
	mitmProtocolExchangeG1()

	fmt.Println("\n\ng=p exchange")
	mitmProtocolExchangeGEqualsP()

	fmt.Println("\n\ng=p-1 exchange")
	mitmProtocolExchangeGEqualsPMinusOne()
}
