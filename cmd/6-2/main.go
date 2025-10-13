package main

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/bigcbrt"
	"github.com/benweissmann/cryptopals/pkg/rsa"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// this is like rsa.PadHashForSignature, but it uses the shortest
// permissible padding (a single 0xff byte) and then pads the end
// with 0s (that will end up filled with garbage during verification)
//
// Having the significant part of the signed data at the front allows
// us to forge a signature by taking the cube-root of this data-- even
// though an integer cube root will have a remainer (so it won't cube
// directly back to the original data), that remainer will be in the low
// bytes (that are insignificant 0s in this "forgable" padded hash) so it
// doesn't matter. The high bytes will be correct, and our loose verification
// routine will correctly verify those and ignore the garbage that ends up
// after them.
func makeForgablePaddedHash(hash []byte, padLenBits int) []byte {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(hash)
	})

	asn1Hash, err := b.Bytes()
	if err != nil {
		panic(err)
	}

	paddingLenBytes := (padLenBits / 8) - len(asn1Hash)
	zeroByteCount := paddingLenBytes - 4
	if zeroByteCount < 1 {
		panic("nout enough space for padding")
	}

	return bytes.Join([][]byte{
		{0x00, 0x01, 0xff, 0x00},
		asn1Hash,
		bytes.Repeat([]byte{0x00}, zeroByteCount),
	}, []byte{})
}

func main() {
	data := []byte("hi mom")

	// discard the private key
	pubkey := rsa.NewKeypair().PublicKey()

	hashToSign := rsa.Sha1HashForSignature(data)
	forgable := makeForgablePaddedHash(hashToSign, rsa.KEY_SIZE)

	fmt.Printf("Forgable : %x\n", forgable)

	dataInt := (&big.Int{}).SetBytes(forgable)
	forgedSig, rem := bigcbrt.Cbrt(dataInt)

	forgedSigBytes := forgedSig.FillBytes(make([]byte, rsa.KEY_SIZE/8))
	remBytes := rem.FillBytes(make([]byte, rsa.KEY_SIZE/8))

	fmt.Printf("Sig      : %x\n", forgedSigBytes)
	fmt.Printf("Rem      : %x\n", remBytes)

	ok, err := pubkey.SloppyVerify(data, forgedSigBytes)
	if !ok {
		panic(err)
	}

	fmt.Println("Pass!")
}
