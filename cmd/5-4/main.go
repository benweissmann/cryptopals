package main

import (
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/srp"
)

func main() {
	// server
	server := srp.NewSRPServer("foo@example.com", "hello world!")
	sess1 := server.NewSession()

	// client
	salt, sess1ServerPubKey := sess1.ParamsForClient("foo@example.com")
	sess1ClientToken, sess1ClientPubKey := srp.ComputeSRPClientToken("hello world!", salt, sess1ServerPubKey)

	// login
	sess1OK := sess1.ValidateLogin(sess1ClientToken, sess1ClientPubKey)
	if !sess1OK {
		panic("Session 1 failed")
	}

	sess2 := server.NewSession()
	salt, sess2ServerPubKey := sess2.ParamsForClient("foo@example.com")

	sess2ClientToken, sess2ClientPubKey := srp.ComputeSRPClientToken("goodbye world!", salt, sess2ServerPubKey)

	sess2OK := sess2.ValidateLogin(sess2ClientToken, sess2ClientPubKey)
	if sess2OK {
		panic("Session 2 passed")
	}

	fmt.Println("Pass!")
}
