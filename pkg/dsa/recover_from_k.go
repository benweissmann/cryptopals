package dsa

import (
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/sha1"
)

// Recovers the private key using a message, its signature, the public key,
// and a known value of k.
func RecoverPrivateKeyFromK(k *big.Int, m []byte, sig *Signature, pubKey *PublicKey) *Keypair {
	q := pubKey.Params.Q

	sk := (&big.Int{}).Mul(sig.S, k)
	sk.Mod(sk, q)

	skMinusHash := (&big.Int{}).Sub(sk, sha1.HashToBigInt(m))
	sk.Mod(skMinusHash, q)

	x := (&big.Int{}).Mul(skMinusHash, (&big.Int{}).ModInverse(sig.R, q))
	x.Mod(x, q)

	return &Keypair{
		Params: pubKey.Params,
		X:      x,
		Y:      pubKey.Y,
	}
}
