package main

import (
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/bleichenbacheroracle"
	"github.com/benweissmann/cryptopals/pkg/rsa"
)

func main() {
	keypair := rsa.NewKeypairWithParams(
		256,
		rsa.DefaultE,
	)

	oracle := bleichenbacheroracle.MakeOracle(keypair)

	mBytes := bleichenbacheroracle.PKCS15Pad([]byte("kick it, CC"), 256)
	m := (&big.Int{}).SetBytes(mBytes)
	c := keypair.PublicKey().Encrypt(m)

	decryptedM := bleichenbacheroracle.OracleAttack(oracle, keypair.PublicKey(), c)
	fmt.Println(string(decryptedM.Bytes()))
}
