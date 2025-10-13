package main

import (
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/bigcbrt"
	"github.com/benweissmann/cryptopals/pkg/rsa"
)

// computes a * b * invmod(c, n)
func combine(a, b, c, n *big.Int) *big.Int {
	im := (&big.Int{}).ModInverse(c, n)
	p1 := (&big.Int{}).Mul(a, b)

	return (&big.Int{}).Mul(p1, im)
}

func main() {
	k0 := rsa.NewKeypair().PublicKey()
	k1 := rsa.NewKeypair().PublicKey()
	k2 := rsa.NewKeypair().PublicKey()

	c0 := k0.EncryptStringToInt("Hello world!")
	c1 := k1.EncryptStringToInt("Hello world!")
	c2 := k2.EncryptStringToInt("Hello world!")

	n0 := k0.N()
	n1 := k1.N()
	n2 := k2.N()

	n012 := (&big.Int{}).Mul(n0, n1)
	n012.Mul(n012, n2)

	ms0 := (&big.Int{}).Mul(n1, n2)
	ms1 := (&big.Int{}).Mul(n0, n2)
	ms2 := (&big.Int{}).Mul(n0, n1)

	r := (&big.Int{}).Add(combine(c0, ms0, ms0, n0), combine(c1, ms1, ms1, n1))
	r.Add(r, combine(c2, ms2, ms2, n2))
	r.Mod(r, n012)

	cleartext, _ := bigcbrt.Cbrt(r)
	fmt.Println(string(cleartext.Bytes()))
}
