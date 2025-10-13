package main

import (
	cryptoRand "crypto/rand"
	"fmt"
	"math"
	rand "math/rand/v2"
	"time"

	"github.com/benweissmann/cryptopals/pkg/mt"
)

func crackMtCrypt(ciphertext []byte) uint16 {
	out := make([]byte, len(ciphertext))
	for i := 0; i < math.MaxUint16; i++ {
		crypter := mt.NewMTCrypter(uint16(i))

		crypter.CryptBlocks(out, ciphertext)
		if string(out[len(out)-14:]) == "AAAAAAAAAAAAAA" {
			return uint16(i)
		}
	}

	panic("Could not crack cipher")
}

func genPRNGToken() uint32 {
	now := uint32(time.Now().Unix()) - uint32(rand.N(1000))
	prng := mt.NewGenerator(now)

	return prng.Rand()
}

func isPRNGToken(tok uint32) bool {
	now := time.Now().Unix()
	for i := now; i > (now - 1000); i-- {
		prng := mt.NewGenerator(uint32(i))
		if prng.Rand() == tok {
			return true
		}
	}

	return false
}

func main() {
	// Crack MT cipher
	seed := uint16(rand.N(math.MaxUint16))
	fmt.Printf("Key: %d\n", seed)

	padding := make([]byte, rand.N(100))
	_, randErr := cryptoRand.Read(padding)
	if randErr != nil {
		panic(randErr.Error())
	}

	cleartext := append(padding, []byte("AAAAAAAAAAAAAA")...)
	crypter := mt.NewMTCrypter(seed)
	ciphertext := make([]byte, len(cleartext))
	crypter.CryptBlocks(ciphertext, cleartext)

	fmt.Printf("Cracked: %d\n", crackMtCrypt(ciphertext))

	// Detect PRNG token
	for range 10 {
		tok := genPRNGToken()
		if !isPRNGToken(tok) {
			panic(fmt.Sprintf("Failed to detect %d as prng token", tok))
		}
	}

	for range 10 {
		tok := rand.Uint32()
		if isPRNGToken(tok) {
			panic(fmt.Sprintf("Mis-detected %d as prng token", tok))
		}
	}

	fmt.Println("Passed prng detection test")
}
