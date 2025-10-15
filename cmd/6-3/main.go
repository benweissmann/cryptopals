package main

import (
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/dsa"
	"github.com/benweissmann/cryptopals/pkg/sha1"
)

func main() {
	params := dsa.DefaultParams()

	pubKey := &dsa.PublicKey{
		Params: params,
		Y: convert.ParseHexToBigInt(
			"084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4" +
				"abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004" +
				"e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed" +
				"1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b" +
				"bb283e6633451e535c45513b2d33c99ea17"),
	}

	msg := []byte("For those that envy a MC it can be hazardous to your health\n" +
		"So be friendly, a matter of life and death, just like a etch-a-sketch\n")

	msgDigest := sha1.HashToBigInt(msg)

	fmt.Printf("Message digest: %x\n", msgDigest)

	sig := &dsa.Signature{
		R: convert.ParseDecimalToBigInt("548099063082341131477253921760299949438196259240"),
		S: convert.ParseDecimalToBigInt("857042759984254168557880549501802188789837994940"),
	}

	// guess k
	var keypair *dsa.Keypair
	for k := int64(1); k < 1<<16; k++ {
		bigK := big.NewInt(k)
		recovered := dsa.RecoverPrivateKeyFromK(bigK, msg, sig, pubKey)

		testSig := recovered.SignWithGivenK(msg, bigK)
		if testSig.R.Cmp(sig.R) == 0 && testSig.S.Cmp(sig.S) == 0 {
			keypair = recovered
			break
		}
	}

	if keypair == nil {
		panic("Failed to find K")
	}

	privKeyHex := fmt.Sprintf("%x", keypair.X)
	fmt.Printf("Found key: %x\n", privKeyHex)

	kSum := sha1.New()
	kSum.Write([]byte(privKeyHex))

	fmt.Printf("Digest: %x\n", kSum.Sum([]byte{}))
}
