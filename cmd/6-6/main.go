package main

import (
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/rsa"
)

var two = big.NewInt(2)

// Returns true if the plaintext is even; false if it is odd
func oracle(keypair *rsa.Keypair, ciphertext *big.Int) bool {
	plaintext := keypair.Decrypt(ciphertext)

	return (&big.Int{}).Mod(plaintext, two).Cmp(big.NewInt(0)) == 0
}

func main() {
	keypair := rsa.NewKeypair()
	pubkey := keypair.PublicKey()
	ciphertext := pubkey.Encrypt(
		convert.ParseBase64ToBigInt("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="),
	)

	min := big.NewInt(0)
	max := pubkey.N()

	testCiphertext := (&big.Int{}).Set(ciphertext)

	// Can multiply the ciphertext by this (2^e mod n) to double the plaintext
	plaintextDoubler := (&big.Int{}).Exp(two, rsa.DefaultE, pubkey.N())

	for min.Cmp(max) < 0 {
		fmt.Println(string(max.Bytes()))

		// Multiply test ciphertext by 2^e mod n to double the plaintext
		testCiphertext.Mul(testCiphertext, plaintextDoubler)

		// Calculate the midpoint
		midpoint := (&big.Int{}).Add(min, max)
		midpoint.Div(midpoint, two)

		if oracle(keypair, testCiphertext) {
			// plaintext was even -- did not wrap the modules; we're in the bottom
			// half of the range
			max = midpoint
		} else {
			// top half of the range
			min = midpoint
		}
	}

	fmt.Println(string(max.Bytes()))
}
