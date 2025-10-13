package main

import (
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/rsa"
)

func main() {
	keypair := rsa.NewKeypair()
	ciphertext := keypair.PublicKey().EncryptString("Hello world!")

	fmt.Println(ciphertext)

	cleartext := keypair.DecryptBytes(ciphertext)
	fmt.Println(cleartext)
}
