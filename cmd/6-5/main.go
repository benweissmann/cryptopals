package main

import (
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/dsa"
)

func tamperG0() {
	goodParams := dsa.DefaultParams()
	badParams := &dsa.Params{
		P:                    goodParams.P,
		Q:                    goodParams.Q,
		G:                    big.NewInt(0),
		SkipZeroVerification: true,
	}

	keypair := dsa.NewKeypair(badParams)

	msg := []byte("Hello, world")
	sig := keypair.Sign(msg)

	fmt.Printf("Signed: %s\nr: %x\ns: %s\n", msg, sig.R, sig.S)

	// That sig should work for other messages
	msg2 := []byte("Goodbye, world")
	ok, err := keypair.PublicKey().Verify(msg2, sig)
	if !ok {
		panic(err)
	}

	// random sig will also work
	randomSig := &dsa.Signature{
		R: big.NewInt(0),
		S: big.NewInt(1234),
	}

	ok, err = keypair.PublicKey().Verify(msg2, randomSig)
	if !ok {
		panic(err)
	}

	fmt.Println("Successfully forged with g=0")
}

func tamperG1() {
	// g = p+1 = 1 mod p
	goodParams := dsa.DefaultParams()
	badParams := &dsa.Params{
		P:                    goodParams.P,
		Q:                    goodParams.Q,
		G:                    (&big.Int{}).Add(goodParams.P, big.NewInt(1)),
		SkipZeroVerification: true,
	}

	keypair := dsa.NewKeypair(badParams)

	// Generate the magic signature
	// r = y^z % p % q
	// s = r/z mod q

	z := big.NewInt(1234)

	r := (&big.Int{}).Exp(keypair.PublicKey().Y, z, badParams.P)
	r.Mod(r, badParams.Q)

	s := (&big.Int{}).Mul(r, (&big.Int{}).ModInverse(z, badParams.Q))
	s.Mod(s, badParams.Q)

	magicSig := &dsa.Signature{
		R: r,
		S: s,
	}

	ok, err := keypair.PublicKey().Verify([]byte("Hello, world"), magicSig)
	if !ok {
		panic(err)
	}

	ok, err = keypair.PublicKey().Verify([]byte("Goodbye, world"), magicSig)
	if !ok {
		panic(err)
	}

	fmt.Println("Successfully forged with g=1 mod p")
}

func main() {
	tamperG0()
	tamperG1()
}
