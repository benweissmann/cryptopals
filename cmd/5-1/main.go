package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/dh"
)

func smallDH() {
	p := big.NewInt(37)
	g := big.NewInt(5)

	aPriv, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err.Error())
	}

	var aPub big.Int
	aPub.Exp(g, aPriv, p)

	bPriv, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err.Error())
	}

	var bPub big.Int
	bPub.Exp(g, bPriv, p)

	var aSession big.Int
	aSession.Exp(&bPub, aPriv, p)

	var bSession big.Int
	bSession.Exp(&aPub, bPriv, p)

	fmt.Printf("%s / %s\n", aSession.String(), bSession.String())

	if aSession.Cmp(&bSession) == 0 {
		fmt.Println("pass!")
	} else {
		fmt.Println("fail :(")
	}
}

func bigDH() {
	a, err := dh.GenerateKeypair()
	if err != nil {
		panic(err.Error())
	}

	b, err := dh.GenerateKeypair()
	if err != nil {
		panic(err.Error())
	}

	aSession := a.SessionKey(b.PubKey())
	bSession := b.SessionKey(a.PubKey())

	fmt.Printf("%s / %s\n", aSession.String(), bSession.String())

	if aSession.Cmp(bSession) == 0 {
		fmt.Println("pass!")
	} else {
		fmt.Println("fail :(")
	}
}

func main() {
	smallDH()
	bigDH()
}
