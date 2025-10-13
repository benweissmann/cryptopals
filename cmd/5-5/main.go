package main

import (
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/dh"
	"github.com/benweissmann/cryptopals/pkg/srp"
)

func main() {
	// server
	server := srp.NewSRPServer("foo@example.com", "hello world!")
	sess := server.NewSession()

	// client
	salt, _ := sess.ParamsForClient("foo@example.com")

	// login, using 0 public key
	fakeClientPub1 := big.NewInt(0)
	fakeS := srp.ComputeK(big.NewInt(0))
	fakeToken := srp.ComputeFinalHmac(fakeS, salt)

	sess1OK := sess.ValidateLogin(fakeToken, fakeClientPub1)
	if !sess1OK {
		panic("Session 2 failed")
	}

	fakeClientPub2 := (&big.Int{}).Mul(big.NewInt(5), dh.DefaultP)
	sess2OK := sess.ValidateLogin(fakeToken, fakeClientPub2)
	if !sess2OK {
		panic("Session 2 failed")
	}

	fmt.Println("Broke SRP!")
}
