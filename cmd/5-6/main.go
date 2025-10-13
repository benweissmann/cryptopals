package main

import (
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/srplite"
)

func healthyExchange() {
	s := srplite.NewSRPServer("foo@example.com", "hello")

	c := srplite.NewClientSession()

	sess := s.NewSession("foo@example.com", c.PubKey())
	salt, bPub, u := sess.ParamsForClient("foo@example.com")

	ok := sess.ValidateLogin(c.ComputeSRPClientToken("hello", salt, bPub, u))

	if !ok {
		fmt.Println("Failed healthy exchange")
		return
	}

	fmt.Println("Passed healthy exchange")
}

func wrongPwExchange() {
	s := srplite.NewSRPServer("foo@example.com", "hello")

	c := srplite.NewClientSession()

	sess := s.NewSession("foo@example.com", c.PubKey())
	salt, bPub, u := sess.ParamsForClient("foo@example.com")

	ok := sess.ValidateLogin(c.ComputeSRPClientToken("world", salt, bPub, u))

	if ok {
		fmt.Println("Failed bad password exchange")
		return
	}

	fmt.Println("Passed bad password exchange")
}

func crackPwExchange() {
	s := srplite.NewSRPServer("foo@example.com", "hello")

	c := srplite.NewClientSession()

	sess := s.NewSession("foo@example.com", c.PubKey())
	salt, bPub, u := sess.EvilParamsForClient("foo@example.com")

	crackedPw := sess.CrackPassword(c.ComputeSRPClientToken("hello", salt, bPub, u))

	fmt.Printf("Cracked password: %s\n", crackedPw)
}

func main() {
	healthyExchange()
	wrongPwExchange()
	crackPwExchange()
}
