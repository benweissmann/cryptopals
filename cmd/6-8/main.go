package main

import (
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/bleichenbacheroracle"
	"github.com/benweissmann/cryptopals/pkg/rsa"
)

func main() {
	keypair := rsa.NewKeypairWithParams(
		768,
		rsa.DefaultE,
	)

	oracle := bleichenbacheroracle.MakeOracle(keypair)

	mBytes := bleichenbacheroracle.PKCS15Pad([]byte("lorem i lorem ipsum lorem ipsum lorem ipsum lorem ipsum longer message... kick it, CC"), 768)
	m := (&big.Int{}).SetBytes(mBytes)
	c := keypair.PublicKey().Encrypt(m)

	decryptedM := bleichenbacheroracle.OracleAttack(oracle, keypair.PublicKey(), c)
	fmt.Println(string(decryptedM.Bytes()))
}
